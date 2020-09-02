#!/usr/bin/env python

"""
Wrapper script for executing Cloudify operations from CI/CD products.
It uses a combination of CLI and REST API calls with the intention of
making the usage of Cloudify from CI/CD products as effortless as possible.
"""
from __future__ import print_function

import argparse
import json
import httplib
import logging
import os
import shutil
import subprocess
import sys
import time
import tempfile

import yaml

from cloudify_cli.constants import (
    CLOUDIFY_USERNAME_ENV,
    DEFAULT_TENANT_NAME
)
from cloudify_cli.cli.cfy import pass_client
from cloudify_cli.logger import get_events_logger
from cloudify_cli.execution_events_fetcher import wait_for_execution
from cloudify_rest_client.executions import Execution
from cloudify_rest_client.exceptions import CloudifyClientError

logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(message)s")
logger = logging.getLogger('cfy-ci')


OMITTED_ARG = "-"
CLOUDIFY_HOST_ENV = "CLOUDIFY_HOST"
CLOUDIFY_SSL_ENV = "CLOUDIFY_SSL"
# Theoretically I would have liked to use the standard environment variable
# for this (defined in cloudify_cli.constants; "CLOUDIFY_TENANT"), however that
# ends up triggering a bug in the CLI.
#
# When we initialize the profile (in the initialize() function), we must do so
# with the tenant name injected into the profile; we must not leave it empty.
# Otherwise, REST calls would fail because @pass_client wouldn't pass a tenant
# to the REST call.
#
# However, if we inject the tenant to the profile, and the "CLOUDIFY_TENANT" environment
# variable is defined, then we get an error message that the tenant is defined
# in both the profile and an environment variable.
#
# To work around that, I invented a new environment variable.
CLOUDIFY_TENANT_NAME_ENV = "CLOUDIFY_TENANT_NAME"


def read_json_or_yaml(path):
    # We assume here, of course, that any JSON file is also a YAML file.
    with open(path, 'r') as f:
        return yaml.load(f)


def initialize(**kwargs):
    # Calls the CLI to set a profile. This should normally only happen once.
    manager_host = os.environ[CLOUDIFY_HOST_ENV]
    manager_user = os.environ[CLOUDIFY_USERNAME_ENV]
    manager_tenant = os.environ.get(CLOUDIFY_TENANT_NAME_ENV, DEFAULT_TENANT_NAME)
    use_ssl = os.environ.get(CLOUDIFY_SSL_ENV, '').lower() != 'false'

    cmdline = [
        'cfy', 'profile', 'use', manager_host,
        '-t', manager_tenant
    ]
    if use_ssl:
        cmdline.append('--ssl')

    logger.info("Initializing; host=%s, user=%s, tenant=%s", manager_host, manager_user, manager_tenant)
    subprocess.check_call(cmdline)
    logger.info("Profile created successfully")


def upload_blueprint(name, path):
    subprocess.check_call([
        'cfy', 'blueprints', 'upload', path,
        '-b', name
    ])


@pass_client()
def _create_deployment(name, blueprint_name, inputs, client):
    cmdline = [
        'cfy', 'deployments', 'create', name,
        '-b', blueprint_name
    ]
    # Handle the inputs: if a string - treat as a path to inputs file.
    # If a dict - treat as actual inputs and use a temporary file to hold them.
    temp_inputs_file = None
    if inputs:
        if type(inputs) == dict:
            with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as temp_inputs_file:
                logger.info("Created temporary file for inputs: %s", temp_inputs_file.name)
                yaml.safe_dump(inputs, temp_inputs_file)
                inputs_file_name = temp_inputs_file.name
        elif type(inputs) == str:
            inputs_file_name = inputs
        else:
            raise Exception("Unhandled inputs type: %s" % type(inputs))
        cmdline.extend(['-i', inputs_file_name])
    try:
        subprocess.check_call(cmdline)
    finally:
        if temp_inputs_file:
            logger.info("Deleting temporary file: %s", temp_inputs_file.name)
            os.remove(temp_inputs_file.name)
    # Now wait until the deployment deletion ended.
    # Since there's no way to get the execution ID of the deployment creation,
    # we need to look it up (see https://cloudifysource.atlassian.net/browse/CY-2385).
    executions = client.executions.list(deployment_id=name)
    if len(executions) != 1:
        raise Exception("Unexpected number of executions for deployment '%s': %d" % (name, len(executions)))
    execution = wait_for_execution(
        client, executions[0], get_events_logger(False), True, timeout=None, logger=logger)
    if execution.status != Execution.TERMINATED:
        raise Exception("Unexpected status of execution %s: %s" % (execution.id, execution.status))


def _start_and_follow_execution(client, deployment_id, workflow_id, parameters):
    # Use REST here, because "cfy executions start" ends with a zero
    # even if the execution fails.
    execution = client.executions.start(deployment_id, workflow_id, parameters)
    execution = wait_for_execution(client, execution, get_events_logger(False), True, timeout=None, logger=logger)
    if execution.status != Execution.TERMINATED:
        raise Exception("Unexpected status of execution %s: %s" % (execution.id, execution.status))


@pass_client()
def install(name, client):
    _start_and_follow_execution(client, name, 'install', None)


@pass_client()
def uninstall(name, ignore_failure, client):
    _start_and_follow_execution(client, name, 'uninstall', {
        'ignore_failure': ignore_failure
    })


@pass_client()
def _delete_deployment(name, client):
    subprocess.check_call([
        'cfy', 'deployments', 'delete', name
    ])
    # Wait until the deployment is actually deleted, as "cfy deployments delete"
    # is asynchronous.
    while True:
        try:
            logger.info("Waiting for the deployment to be deleted...")
            client.deployments.get(name)
            time.sleep(1)
        except CloudifyClientError as ex:
            if ex.status_code == httplib.NOT_FOUND:
                logger.exception("Deployment ended")
                break
            raise


def write_environment_outputs(name, outputs_file):
    if not outputs_file:
        return
    temp_dir = tempfile.mkdtemp()
    try:
        logger.info("Getting environment's outputs")
        with tempfile.NamedTemporaryFile(dir=temp_dir, delete=False) as temp_outputs:
            subprocess.check_call(['cfy', 'deployments', 'outputs', name, '--json'], stdout=temp_outputs)
        logger.info("Getting environment's capabilities")
        with tempfile.NamedTemporaryFile(dir=temp_dir, delete=False) as temp_caps:
            subprocess.check_call(['cfy', 'deployments', 'capabilities', name, '--json'], stdout=temp_caps)

        with open(temp_outputs.name, 'r') as f:
            outputs = json.load(f)
        with open(temp_caps.name, 'r') as f:
            capabilities = json.load(f)

        env_data = {
            "deployment_id": name,
            "outputs": outputs,
            "capabilities": capabilities
        }

        logger.info("Writing environment data to %s", outputs_file)
        with open(outputs_file, 'w') as f:
            json.dump(env_data, f)
    finally:
        shutil.rmtree(temp_dir)


def prepare_invocation_params(func):
    def wrapper(*args, **kwargs):
        # kwargs.pop('func', None)
        # invocation_params_file = kwargs.pop("invocation_params_file", None)
        # invocation_params = {}
        # if invocation_params_file:
        #     invocation_params = read_json_or_yaml(invocation_params_file)
        # for arg_name, arg_value in kwargs.iteritems():
        #     if arg_value is not None:
        #         invocation_params[arg_name] = arg_value
        # print(invocation_params)
        # func(*args, **invocation_params)
        func(*args, **kwargs)

    return wrapper


def create_deployment(name, blueprint, inputs_file, **kwargs):
    _create_deployment(name, blueprint, inputs_file)


def create_environment(name, blueprint, inputs_file, outputs_file, **kwargs):
    logger.info("Creating environment; name=%s, blueprint=%s, inputs=%s, outputs=%s",
                name, blueprint, inputs_file, outputs_file)
    blueprint_name = 'cfyci-%s-bp' % name
    upload_blueprint(blueprint_name, blueprint)
    _create_deployment(name, blueprint_name, inputs_file)
    install(name)
    write_environment_outputs(name, outputs_file)


class CfyIntegration(object):
    """
    Root class for all integrations.
    """
    def __init__(self, deployment_id, outputs_file):
        self._deployment_id = deployment_id
        self._outputs_file = outputs_file

    def blueprint_name(self):
        raise NotImplementedError()

    def prepare_inputs(self):
        raise NotImplementedError()

    @classmethod
    def parse_environment_mapping(cls, str_list):
        mapping = {}
        str_list = str_list or []
        for item in str_list:
            if "=" in item:
                source, target = item.split("=")
            else:
                source = target = item
            mapping[source] = target
        return mapping

    def execute(self):
        inputs = self.prepare_inputs()
        _create_deployment(self._deployment_id, self.blueprint_name(), inputs)
        install(self._deployment_id)
        write_environment_outputs(self._deployment_id, self._outputs_file)


class CfyTerraformIntegration(CfyIntegration):
    def __init__(self, name, outputs_file, module, variables, environment, environment_mapping):
        CfyIntegration.__init__(self, name, outputs_file)
        self._module = module
        self._variables = variables
        self._environment = environment
        self._environment_mapping = CfyIntegration.parse_environment_mapping(
            environment_mapping)

    def blueprint_name(self):
        return 'cfy-terraform-1.0'

    def prepare_inputs(self):
        inputs = {
            'module_source': self._module
        }
        if self._variables:
            inputs['variables'] = read_json_or_yaml(self._variables)
        for env_var, key in [
            ('TERRAFORM_EXECUTABLE', 'terraform_executable'),
            ('TERRAFORM_PLUGINS_DIR', 'terraform_plugins_dir'),
            ('TERRAFORM_STORAGE_DIR', 'terraform_storage_dir')
        ]:
            if env_var in os.environ:
                inputs.setdefault(key, os.environ[env_var])
        env_vars = {}
        if self._environment:
            env_vars.update(read_json_or_yaml(self._environment))
        for key, value in self._environment_mapping.iteritems():
            if key in os.environ:
                env_vars[value] = os.environ[key]
        if env_vars:
            inputs['environment_variables'] = env_vars

        return inputs


class CfyARMIntegration(CfyIntegration):
    def __init__(self, name, outputs_file, resource_group, template_file, parameters_file, credentials_file, location):
        CfyIntegration.__init__(self, name, outputs_file)
        self._resource_group = resource_group
        self._template_file = template_file
        self._parameters_file = parameters_file
        self._credentials_file = credentials_file
        self._location = location

    def blueprint_name(self):
        return 'cfy-azure-arm-1.0'

    def prepare_inputs(self):
        if self._credentials_file:
            azure_creds = read_json_or_yaml(self._credentials_file)
        else:
            azure_creds = {}
        for env_var, key in [
            ('AZURE_SUBSCRIPTION_ID', 'azure_subscription_id'),
            ('AZURE_TENANT_ID', 'azure_tenant_id'),
            ('AZURE_CLIENT_ID', 'azure_client_id'),
            ('AZURE_CLIENT_SECRET', 'azure_client_secret')
        ]:
            if env_var in os.environ:
                azure_creds.setdefault(key, os.environ[env_var])

        inputs = dict(azure_creds)
        if self._location:
            inputs['location'] = self._location
        inputs['resource_group_name'] = self._resource_group
        if self._parameters_file:
            inputs['parameters'] = read_json_or_yaml(self._parameters_file)
        inputs['template'] = read_json_or_yaml(self._template_file)
        return inputs


class CfyCFNIntegration(CfyIntegration):
    def __init__(self, name, outputs_file, stack_name, template_url, parameters_file, credentials_file, region_name):
        CfyIntegration.__init__(self, name, outputs_file)
        self._stack_name = stack_name
        self._template_url = template_url
        self._parameters_file = parameters_file
        self._credentials_file = credentials_file
        self._region_name = region_name

    def blueprint_name(self):
        return 'cfy-cloudformation-1.0'

    def prepare_inputs(self):
        if self._credentials_file:
            aws_creds = read_json_or_yaml(self._credentials_file)
        else:
            aws_creds = {}
        for env_var, key in [
            ('AWS_ACCESS_KEY_ID', 'aws_access_key_id'),
            ('AWS_SECRET_ACCESS_KEY', 'aws_secret_access_key'),
            ('AWS_REGION', 'aws_region_name')
        ]:
            if env_var in os.environ:
                aws_creds.setdefault(key, os.environ[env_var])

        inputs = dict(aws_creds)
        if self._region_name:
            inputs['aws_region_name'] = self._region_name
        inputs['stack_name'] = self._stack_name
        if self._parameters_file:
            parameters = read_json_or_yaml(self._parameters_file)
            inputs['parameters'] = [{
                'ParameterKey': key,
                'ParameterValue': value
            } for key, value in parameters.iteritems()]
        inputs['template_url'] = self._template_url
        return inputs


class CfyKubernetesIntegration(CfyIntegration):
    def __init__(
            self, name, outputs_file, gcp_credentials_file, token, token_file, master_host,
            namespace, app_definition_file, ca_cert_file, ssl_cert_file, ssl_key_file,
            skip_ssl_verification, other_options_file, validate_status, allow_node_redefinition, debug
    ):
        CfyIntegration.__init__(self, name, outputs_file)
        self._gcp_credentials_file = gcp_credentials_file
        self._token = token
        self._token_file = token_file
        self._master_host = master_host
        self._namespace = namespace
        self._app_definition_file = app_definition_file
        self._ca_cert_file = ca_cert_file
        self._ssl_cert_file = ssl_cert_file
        self._ssl_key_file = ssl_key_file
        self._skip_ssl_verification = skip_ssl_verification
        self._other_options_file = other_options_file
        self._validate_status = validate_status
        self._allow_node_redefinition = allow_node_redefinition
        self._debug = debug

    def blueprint_name(self):
        return 'cfy-kubernetes-1.0'

    def prepare_inputs(self):
        if sum(1 for x in [
            self._gcp_credentials_file,
            self._token_file,
            self._token
        ] if x is not None) != 1:
            raise Exception("Exactly one of (GCP credentials file, token file, token) must be provided")

        api_options = {
            "host": self._master_host,
            "verify_ssl": not self._skip_ssl_verification,
            "debug": self._debug
        }
        client_config_configuration = {
            "api_options": api_options
        }
        client_config = {
            "configuration": client_config_configuration
        }
        options = {}

        if self._other_options_file:
            options.update(
                read_json_or_yaml(self._other_options_file))

        if self._gcp_credentials_file:
            logger.info("Reading GCP credentials from %s", self._gcp_credentials_file)
            gcp_credentials = read_json_or_yaml(self._gcp_credentials_file)
            client_config["authentication"] = {
                "gcp_service_account": gcp_credentials
            }
        else:
            api_key = self._token
            if not api_key:
                logger.info("Reading API token from %s", self._token_file)
                with open(self._token_file, 'r') as f:
                    api_key = f.read()
            else:
                logger.info("Using API token provided as string")
            api_options["api_key"] = api_key

        if self._ca_cert_file:
            api_options["ssl_ca_cert"] = self._ca_cert_file
        if self._ssl_cert_file:
            api_options["cert_file"] = self._ssl_cert_file
        if self._ssl_key_file:
            api_options["key_file"] = self._ssl_key_file
        if self._namespace:
            options["namespace"] = self._namespace

        inputs = {
            "client_config": client_config,
            "definition": read_json_or_yaml(self._app_definition_file),
            "options": options,
            "validate_status": self._validate_status,
            "allow_node_redefinition": self._allow_node_redefinition
        }
        return inputs


@prepare_invocation_params
def terraform(
        name, module, outputs_file, variables, environment,
        environment_mapping, **kwargs):
    CfyTerraformIntegration(
        name, outputs_file, module, variables, environment,
        environment_mapping).execute()


def arm(
        name, resource_group, template_file, parameters_file, credentials_file,
        location, outputs_file, **kwargs):
    CfyARMIntegration(
        name, outputs_file, resource_group, template_file, parameters_file,
        credentials_file, location).execute()


def cfn(
        name, outputs_file, stack_name, template_url, parameters_file, credentials_file,
        region_name, **kwargs):
    CfyCFNIntegration(
        name, outputs_file, stack_name, template_url, parameters_file,
        credentials_file, region_name).execute()


def kubernetes(
        name, outputs_file, gcp_credentials_file, token, token_file, master_host, namespace,
        app_definition_file, ca_cert_file, ssl_cert_file, ssl_key_file, skip_ssl_verification,
        other_options_file, validate_status, allow_node_redefinition, debug, **kwargs):
    CfyKubernetesIntegration(
        name, outputs_file, gcp_credentials_file, token, token_file, master_host,
        namespace, app_definition_file, ca_cert_file, ssl_cert_file, ssl_key_file,
        skip_ssl_verification, other_options_file, validate_status,
        allow_node_redefinition, debug).execute()


def delete_deployment(name, **kwargs):
    _delete_deployment(name)


def delete_environment(name, ignore_failure, **kwargs):
    logger.info("Deleting environment; name=%s, ignore_failure=%s", name, ignore_failure)
    uninstall(name, ignore_failure)
    _delete_deployment(name)


def main():
    # This makes life easier when we need to call this script when certain
    # parameters are not required by the caller, but the caller must provide
    # *some* value due to how the CI/CD product works. For example, in CircleCI,
    # it is very difficult and cumbersome to dynamically construct a command-line
    # based on conditions. Therefore, we default certain parameters there to a certain
    # value, which is an agreed-upon representation for "I don't really want this".
    def optional_string(s):
        return s if s != OMITTED_ARG else None

    def boolean_string(s):
        if s is None:
            return None
        lower_value = s.lower()
        if lower_value == 'true':
            return True
        if lower_value == 'false':
            return False
        raise Exception("Unrecognized boolean value: '%s'" % s)

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    init_parser = subparsers.add_parser('init')
    init_parser.set_defaults(func=initialize)

    create_deployment_parser = subparsers.add_parser('create-deployment')
    create_deployment_parser.add_argument('--name', required=True)
    create_deployment_parser.add_argument('--blueprint', required=True)
    create_deployment_parser.add_argument('--inputs', dest='inputs_file', type=optional_string)
    create_deployment_parser.set_defaults(func=create_deployment)

    create_environment_parser = subparsers.add_parser('create-environment')
    create_environment_parser.add_argument('--name', required=True)
    create_environment_parser.add_argument('--blueprint', required=True)
    create_environment_parser.add_argument('--inputs', dest='inputs_file', type=optional_string)
    create_environment_parser.add_argument('--outputs', dest='outputs_file', type=optional_string)
    create_environment_parser.set_defaults(func=create_environment)

    integrations_parent = argparse.ArgumentParser(add_help=False)
    integrations_parent.add_argument('--name')
    integrations_parent.add_argument('--invocation-params-file', type=optional_string)
    integrations_parent.add_argument('--outputs', dest='outputs_file', type=optional_string)

    terraform_parser = subparsers.add_parser('terraform', parents=[integrations_parent])
    terraform_parser.add_argument('--module')
    terraform_parser.add_argument('--variables', type=optional_string)
    terraform_parser.add_argument('--environment', type=optional_string)
    terraform_parser.add_argument('--environment-mapping', nargs="*", default=[])
    terraform_parser.set_defaults(func=terraform)

    arm_parser = subparsers.add_parser('arm', parents=[integrations_parent])
    arm_parser.add_argument('--resource-group', required=True)
    arm_parser.add_argument('--template-file', required=True)
    arm_parser.add_argument('--parameters-file', type=optional_string)
    arm_parser.add_argument('--credentials-file', type=optional_string)
    arm_parser.add_argument('--location', type=optional_string)
    arm_parser.set_defaults(func=arm)

    cfn_parser = subparsers.add_parser('cfn', parents=[integrations_parent])
    cfn_parser.add_argument('--stack-name', required=True)
    cfn_parser.add_argument('--template-url', required=True)
    cfn_parser.add_argument('--parameters-file', type=optional_string)
    cfn_parser.add_argument('--credentials-file', type=optional_string)
    cfn_parser.add_argument('--region-name', type=optional_string)
    cfn_parser.set_defaults(func=cfn)

    k8s_parser = subparsers.add_parser('k8s', parents=[integrations_parent])
    k8s_parser.add_argument('--gcp-credentials-file', type=optional_string)
    k8s_parser.add_argument('--token', type=optional_string)
    k8s_parser.add_argument('--token-file', type=optional_string)
    k8s_parser.add_argument('--master-host', required=True)
    k8s_parser.add_argument('--namespace', type=optional_string)
    k8s_parser.add_argument('--app-definition-file', required=True)
    k8s_parser.add_argument('--ca-cert-file', type=optional_string)
    k8s_parser.add_argument('--ssl-cert-file', type=optional_string)
    k8s_parser.add_argument('--ssl-key-file', type=optional_string)
    k8s_parser.add_argument('--skip-ssl-verification', type=boolean_string)
    k8s_parser.add_argument('--other-options-file', type=optional_string)
    k8s_parser.add_argument('--validate-status', type=boolean_string)
    k8s_parser.add_argument('--allow-node-redefinition', type=boolean_string)
    k8s_parser.add_argument('--debug', type=boolean_string)
    k8s_parser.set_defaults(func=kubernetes)

    delete_deployment_parser = subparsers.add_parser('delete-deployment')
    delete_deployment_parser.add_argument('--name', required=True)
    delete_deployment_parser.set_defaults(func=delete_deployment)

    delete_environment_parser = subparsers.add_parser('delete-environment')
    delete_environment_parser.add_argument('--name', required=True)
    delete_environment_parser.add_argument('--ignore-failure', type=boolean_string)
    delete_environment_parser.set_defaults(func=delete_environment)

    args = parser.parse_args()
    args.func(**vars(args))


if __name__ == '__main__':
    main()
