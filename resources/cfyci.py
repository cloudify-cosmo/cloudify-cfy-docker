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
import io
import logging
import os
import subprocess
import sys
import time
import tempfile
import urllib3

from string import Template

import yaml

from cloudify_cli.constants import (
    CLOUDIFY_USERNAME_ENV,
    CLOUDIFY_PASSWORD_ENV,
    CLOUDIFY_TENANT_ENV,
    DEFAULT_TENANT_NAME
)
from cloudify_cli.logger import get_events_logger
from cloudify_cli.env import CLOUDIFY_WORKDIR, get_ssl_trust_all
from cloudify_cli.execution_events_fetcher import wait_for_execution
from cloudify_rest_client.client import CloudifyClient, DEFAULT_PROTOCOL, SECURED_PROTOCOL
from cloudify_rest_client.executions import Execution
from cloudify_rest_client.exceptions import CloudifyClientError

logger_debug = str(os.environ.get('CFYCI_DEBUG', False)).lower() == 'true'
logging.basicConfig(
    stream=sys.stderr,
    level=logging.DEBUG if logger_debug else logging.INFO,
    format="%(message)s")
logger = logging.getLogger('cfy-ci')

IS_GITHUB = 'GITHUB_RUN_ID' in os.environ

OMITTED_ARG = "-"
CLOUDIFY_HOST_ENV = "CLOUDIFY_HOST"
CLOUDIFY_SSL_ENV = "CLOUDIFY_SSL"
DEPLOYMENT_DELETE_TIMEOUT_DEFAULT = 120
# Time, in seconds, to wait for deployment deletion
DEPLOYMENT_DELETE_TIMEOUT = int(os.environ.get(
    'DEPLOYMENT_DELETE_TIMEOUT', str(DEPLOYMENT_DELETE_TIMEOUT_DEFAULT)))


def read_json_or_yaml(path):
    # We assume here, of course, that any JSON file is also a YAML file.
    with io.open(path, 'r', encoding='UTF-8') as f:
        return yaml.load(f)


def _use_ssl():
    """
    Determines if SSL should be used when communicating with Cloudify Manager.
    SSL will be used unless the `CLOUDIFY_SSL` environment variable is defined
    to the value "false" (case-insensitive).
    """
    return os.environ.get(CLOUDIFY_SSL_ENV, '').lower() != 'false'


def _cfy_cli_inner(cmdline, shell=False, capture_stdout=False):
    """
    Lowest layer of calling the Cloudify CLI.
    Typically, you would want to call "_cfy_cli" instead of this one.
    """
    env = dict(os.environ)
    if CLOUDIFY_TENANT_ENV not in env:
        env[CLOUDIFY_TENANT_ENV] = DEFAULT_TENANT_NAME
    # If "trust all" is in effect, then disable this warning and
    # assume the user knows what they're doing.
    if _use_ssl() and get_ssl_trust_all():
        env['PYTHONWARNINGS'] = "ignore:Unverified HTTPS request"
    if shell:
        full_cmdline = "cfy {}".format(cmdline)
    else:
        full_cmdline = ['cfy']
        full_cmdline.extend(cmdline)
    logger.info("Running: %s", full_cmdline)
    if capture_stdout:
        stdout_contents = subprocess.check_output(full_cmdline, env=env, shell=shell)
    else:
        subprocess.check_call(full_cmdline, env=env, shell=shell)
        stdout_contents = None
    return stdout_contents


def _init_profile():
    manager_host = os.environ[CLOUDIFY_HOST_ENV]
    manager_user = os.environ[CLOUDIFY_USERNAME_ENV]

    init_cmdline = [
        'profile', 'use', manager_host
    ]
    if _use_ssl():
        init_cmdline.append('--ssl')

    logger.info("Initializing; host=%s, user=%s", manager_host, manager_user)
    _cfy_cli_inner(init_cmdline)
    logger.info("Profile created successfully")


def _cfy_cli(cmdline, shell=False, capture_stdout=False):
    """
    Use this in order to call the CLI. It checks first to see if a profile needs
    to be created, and creates one if so.
    """
    if not os.path.isdir(CLOUDIFY_WORKDIR):
        logger.info("First-time CLI invocation; creating CLI profile")
        _init_profile()
    return _cfy_cli_inner(cmdline, shell=shell, capture_stdout=capture_stdout)


def with_client(func):
    """
    This wrapper is needed because of a limitation in the CLI's "pass_client" decorator:
    It can't be used from within the same Python process that initialized the profile
    to begin with. In other words, "pass_client" will only work if it is used in an
    invocation *after* "initialize()" was called.
    """
    def wrapper(*args, **kwargs):
        manager_host = os.environ[CLOUDIFY_HOST_ENV]
        manager_user = os.environ[CLOUDIFY_USERNAME_ENV]
        manager_password = os.environ[CLOUDIFY_PASSWORD_ENV]
        manager_tenant = os.environ.get(CLOUDIFY_TENANT_ENV, DEFAULT_TENANT_NAME)
        use_ssl = _use_ssl()
        ssl_trust_all = get_ssl_trust_all()
        # If user wants to trust all certificates, then disable the warning
        # about it and assume (and hope) they know what they're doing.
        if use_ssl and ssl_trust_all:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        client = CloudifyClient(
            host=manager_host,
            username=manager_user,
            password=manager_password,
            tenant=manager_tenant,
            protocol=SECURED_PROTOCOL if use_ssl else DEFAULT_PROTOCOL,
            trust_all=ssl_trust_all
        )
        kwargs['client'] = client
        return func(*args, **kwargs)

    return wrapper


def upload_blueprint(name, path):
    _cfy_cli([
        'blueprints', 'upload', path, '-b', name
    ])


def wait_for_and_validate_execution(client, execution):
    execution = wait_for_execution(
        client, execution, get_events_logger(False), True, timeout=None, logger=logger)
    if execution.status != Execution.TERMINATED:
        raise Exception(
            "Unexpected status of execution {}: {} (expected: {})".format(
                execution.id, execution.status, Execution.TERMINATED))
    return execution


@with_client
def _create_deployment(name, blueprint_name, inputs, client):
    cmdline = [
        'deployments', 'create', name, '-b', blueprint_name
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
            raise Exception(
                "Unhandled inputs type: {}; should be either a dictionary (containing inputs) "
                "or a string (containing a path to a file)".format(type(inputs)))
        cmdline.extend(['-i', inputs_file_name])
    try:
        _cfy_cli(cmdline)
    finally:
        if temp_inputs_file:
            logger.info("Deleting temporary file: %s", temp_inputs_file.name)
            os.remove(temp_inputs_file.name)
    # Now wait until the deployment deletion ended.
    # Since there's no way to get the execution ID of the deployment creation,
    # we need to look it up (see https://cloudifysource.atlassian.net/browse/CY-2385).
    executions = client.executions.list(deployment_id=name)
    if len(executions) != 1:
        raise Exception(
            "Unexpected number of executions for deployment "
            "'{}': {} (should be 1)".format(name, len(executions)))
    wait_for_and_validate_execution(client, executions[0])


def _start_and_follow_execution(client, deployment_id, workflow_id, parameters):
    # Use REST here, because "cfy executions start" ends with a zero
    # even if the execution fails.
    execution = client.executions.start(deployment_id, workflow_id, parameters)
    wait_for_and_validate_execution(client, execution)


@with_client
def install(name, client):
    _start_and_follow_execution(client, name, 'install', None)


@with_client
def uninstall(name, ignore_failure, client):
    _start_and_follow_execution(client, name, 'uninstall', {
        'ignore_failure': ignore_failure
    })


@with_client
def _delete_deployment(name, client):
    _cfy_cli([
        'deployments', 'delete', name
    ])
    # Wait until the deployment is actually deleted, as "cfy deployments delete"
    # is asynchronous.
    ended = False
    initial_time = time.time()
    while time.time() < initial_time + DEPLOYMENT_DELETE_TIMEOUT:
        logger.info(
            "Waiting for the deployment to be deleted (timeout in %d seconds)...",
            initial_time + DEPLOYMENT_DELETE_TIMEOUT - time.time())
        try:
            client.deployments.get(name)
            time.sleep(1)
        except CloudifyClientError as ex:
            if ex.status_code == httplib.NOT_FOUND:
                logger.info("Deployment deleted")
                ended = True
                break
            raise

    if not ended:
        raise Exception("Deployment did not end within {} seconds".format(
            DEPLOYMENT_DELETE_TIMEOUT))


@with_client
def get_environment_data(name, blueprint_id, client):
    outputs = client.deployments.outputs.get(name)
    capabilities = client.deployments.capabilities.get(name)
    return {
        "blueprint_id": blueprint_id,
        "deployment_id": name,
        "outputs": outputs['outputs'],
        "capabilities": capabilities['capabilities']
    }


def write_environment_outputs(name, blueprint_id, outputs_file):
    if not (outputs_file or IS_GITHUB):
        return
    env_data = get_environment_data(name, blueprint_id)
    if IS_GITHUB:
        # Set the environment's data as an output.
        logger.info("Setting environment data output variable: %s", env_data)
        print("::set-output name=environment-data::%s".format(json.dumps(env_data)))
    if outputs_file:
        logger.info("Writing environment data to %s", outputs_file)
        with open(outputs_file, 'w') as f:
            json.dump(env_data, f, indent=4)


def init(**kwargs):
    _init_profile()


def create_deployment(name, blueprint, inputs_file, **kwargs):
    _create_deployment(name, blueprint, inputs_file)


def create_environment(name, blueprint, inputs_file, outputs_file, **kwargs):
    logger.info(
        "Creating environment; name=%s, blueprint=%s, inputs=%s, outputs=%s",
        name, blueprint, inputs_file, outputs_file)
    blueprint_name = 'cfyci-{}-bp'.format(name)
    logger.info("Uploading blueprint: %s", blueprint_name)
    upload_blueprint(blueprint_name, blueprint)
    logger.info("Creating deployment: %s", name)
    _create_deployment(name, blueprint_name, inputs_file)
    logger.info("Running the install workflow")
    install(name)
    write_environment_outputs(name, blueprint_name, outputs_file)


class CfyIntegration(object):
    """
    Root class for all integrations.
    """
    def __init__(self, deployment_id, outputs_file, configuration):
        self._deployment_id = deployment_id
        self._outputs_file = outputs_file
        self._configuration = configuration

    def integration_name(self):
        raise NotImplementedError()

    def prepare_inputs(self):
        raise NotImplementedError()

    @classmethod
    def parse_environment_mapping(cls, str_list):
        mapping = {}
        # On GitHub, we're going to receive a list containing
        # a single item, and that single item is space-delimited.
        # That's due to how GitHub quotes arguments. So...
        logger.debug("str_list=(%s) %s", type(str_list), str_list)

        if IS_GITHUB and str_list:
            str_list = str_list[0].split()
        str_list = str_list or []
        for item in str_list:
            logger.debug("item=%s", item)
            if "=" in item:
                source, target = item.split("=")
            else:
                source = target = item
            mapping[source] = target
        return mapping

    @with_client
    def execute(self, client):
        integration_name = self.integration_name()
        integration_desc = self._configuration['integrations'][integration_name]
        blueprint_name = integration_desc['blueprint_id']
        logger.info("Checking existence of integration blueprint: %s", blueprint_name)
        try:
            client.blueprints.get(blueprint_name)
        except CloudifyClientError as ex:
            if ex.status_code == httplib.NOT_FOUND:
                _cfy_cli([
                    'blueprints', 'upload',
                    self._configuration['integration_blueprints_archive_url'],
                    '-b', blueprint_name,
                    '-n', integration_desc['blueprint_file']
                ])
            else:
                raise
        # If we got here, then the integration blueprint exists.
        logger.info("Creating deployment")
        inputs = self.prepare_inputs()
        _create_deployment(self._deployment_id, blueprint_name, inputs)
        logger.info("Deployment created successfully; installing it")
        install(self._deployment_id)
        logger.info("Installation ended successfully")
        write_environment_outputs(self._deployment_id, blueprint_name, self._outputs_file)


class CfyTerraformIntegration(CfyIntegration):
    def __init__(self, configuration, name, outputs_file, module, variables, environment, environment_mapping, **kwargs):
        CfyIntegration.__init__(self, name, outputs_file, configuration)
        self._module = module
        self._variables = variables
        self._environment = environment
        self._environment_mapping = CfyIntegration.parse_environment_mapping(
            environment_mapping)

    def integration_name(self):
        return 'terraform'

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
    def __init__(self, configuration, name, outputs_file, resource_group, template_file, parameters_file,
                 credentials_file, location, **kwargs):
        CfyIntegration.__init__(self, name, outputs_file, configuration)
        self._resource_group = resource_group
        self._template_file = template_file
        self._parameters_file = parameters_file
        self._credentials_file = credentials_file
        self._location = location

    def integration_name(self):
        return 'arm'

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
    def __init__(self, configuration, name, outputs_file, stack_name, template_url, bucket_name,
                 resource_name, template_file, parameters_file, credentials_file,
                 region_name, **kwargs):
        CfyIntegration.__init__(self, name, outputs_file, configuration)
        self._stack_name = stack_name
        self._template_url = template_url
        self._bucket_name = bucket_name
        self._resource_name = resource_name
        self._template_file = template_file
        self._parameters_file = parameters_file
        self._credentials_file = credentials_file
        self._region_name = region_name

    def integration_name(self):
        return 'cfn'

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

        resource_config_kwargs = {}
        inputs['resource_config'] = {
            'kwargs': resource_config_kwargs
        }

        resource_config_kwargs['StackName'] = self._stack_name
        if self._parameters_file:
            parameters = read_json_or_yaml(self._parameters_file)
            resource_config_kwargs['Parameters'] = [{
                'ParameterKey': key,
                'ParameterValue': value
            } for key, value in parameters.iteritems()]
        if self._template_url:
            logger.info("Will use template from %s", self._template_url)
            resource_config_kwargs['TemplateURL'] = self._template_url
        elif self._template_file:
            logger.info("Reading stack from %s", self._template_file)
            with io.open(self._template_file, 'r', encoding='UTF-8') as f:
                resource_config_kwargs['TemplateBody'] = f.read()
        elif self._bucket_name and self._resource_name:
            # TODO: Add this to the plugin?
            template_url = "https://{}.s3.amazonaws.com/{}".format(self._bucket_name, self._resource_name)
            logger.info("Concluded URL for stack file: %s", template_url)
            resource_config_kwargs['TemplateURL'] = template_url
        else:
            raise Exception(
                "Either template URL, template body, or combination of bucket name "
                "and resource name, must be provided")
        return inputs


class CfyKubernetesIntegration(CfyIntegration):
    def __init__(
            self, configuration, name, outputs_file, gcp_credentials_file, token, token_file, master_host,
            namespace, app_definition_file, ca_cert_file, ssl_cert_file, ssl_key_file,
            skip_ssl_verification, other_options_file, validate_status, allow_node_redefinition, debug,
            **kwargs
    ):
        CfyIntegration.__init__(self, name, outputs_file,configuration)
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

    def integration_name(self):
        return 'kubernetes'

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
                with io.open(self._token_file, 'r', encoding='UTF-8') as f:
                    api_key = f.read()
            else:
                logger.info("Using API token provided as string")
            api_options["api_key"] = api_key

        for x, y in [
            (self._ca_cert_file, "ssl_ca_cert"),
            (self._ssl_cert_file, "cert_file"),
            (self._ssl_key_file, "key_file")
        ]:
            if x:
                api_options[y] = x

        if self._namespace:
            options["namespace"] = self._namespace

        inputs = {
            "client_config": client_config,
            "definition": read_json_or_yaml(self._app_definition_file),
            "options": options
        }
        for x, y in [
            (self._validate_status, "validate_status"),
            (self._allow_node_redefinition, "allow_node_redefinition")
        ]:
            if x is not None:
                inputs[y] = x
        return inputs


def terraform(**kwargs):
    CfyTerraformIntegration(**kwargs).execute()


def arm(**kwargs):
    CfyARMIntegration(**kwargs).execute()


def cfn(**kwargs):
    CfyCFNIntegration(**kwargs).execute()


def kubernetes(**kwargs):
    CfyKubernetesIntegration(**kwargs).execute()


def delete_deployment(name, **kwargs):
    _delete_deployment(name)


@with_client
def delete_environment(name, delete_blueprint, ignore_failure, client, **kwargs):
    logger.info(
        "Deleting environment; name=%s, delete_blueprint=%s, ignore_failure=%s",
        name, delete_blueprint, ignore_failure)
    logger.info("Running the uninstall workflow")
    uninstall(name, ignore_failure)
    # If we're asked to delete the blueprint as well, then get the blueprint
    # ID before we delete the deployment.
    if delete_blueprint:
        deployment = client.deployments.get(name)
        blueprint_id = deployment.blueprint_id
    else:
        blueprint_id = None
    logger.info("Deleting deployment")
    _delete_deployment(name)
    if blueprint_id:
        logger.info("Checking if any deployments exist for blueprint '%s'", blueprint_id)
        deployments = client.deployments.list(blueprint_id=blueprint_id)
        if deployments:
            logger.info("Found at least one more deployment; not deleting blueprint")
        else:
            logger.info("Deleting blueprint: %s", blueprint_id)
            _cfy_cli(['blueprints', 'delete', blueprint_id])


def cli(command, set_output, **kwargs):
    logger.info(
        "Running CLI command: %s", command
    )
    stdout_contents = _cfy_cli(command, shell=True, capture_stdout=set_output)
    if set_output:
        print("::set-output name=cli-output::%s".format(stdout_contents))


def main():
    # This makes life easier when we need to call this script when certain
    # parameters are not required by the caller, but the caller must provide
    # *some* value due to how the CI/CD product works. For example, in CircleCI,
    # it is very difficult and cumbersome to dynamically construct a command-line
    # based on conditions. Therefore, we default certain parameters there to a certain
    # value, which is an agreed-upon representation for "I don't really want this".
    def optional_string(s):
        if s is None or s in[OMITTED_ARG, '']:
            return None
        return s

    def boolean_string(s):
        if s is None or s == '':
            return None
        lower_value = s.lower()
        if lower_value == 'true':
            return True
        if lower_value == 'false':
            return False
        raise Exception("Unrecognized boolean value: '{}'".format(s))

    def optional_existing_path(s):
        filtered = optional_string(s)
        if filtered is None:
            return None
        # Must be path to existing file.
        if not os.path.isfile(filtered):
            raise argparse.ArgumentTypeError("Path not found: {}".format(filtered))
        return filtered

    # On first glance, you may think that we should use mutually exclusive arguments
    # groups. Yeah, I know. However, note that we have to allow all argument combinations,
    # to pass through the parser, because the caller is likely to provide all parameters,
    # with some of them blank.

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    # Currently empty (may add something to it soon...)
    common_parent = argparse.ArgumentParser(add_help=False)

    init_parser = subparsers.add_parser('init', parents=[common_parent])
    init_parser.set_defaults(func=init)

    create_deployment_parser = subparsers.add_parser('create-deployment', parents=[common_parent])
    create_deployment_parser.add_argument('--name', required=True)
    create_deployment_parser.add_argument('--blueprint', required=True)
    create_deployment_parser.add_argument('--inputs', dest='inputs_file', type=optional_existing_path)
    create_deployment_parser.set_defaults(func=create_deployment)

    create_environment_parser = subparsers.add_parser('create-environment', parents=[common_parent])
    create_environment_parser.add_argument('--name', required=True)
    create_environment_parser.add_argument('--blueprint', required=True)
    create_environment_parser.add_argument('--inputs', dest='inputs_file', type=optional_existing_path)
    create_environment_parser.add_argument('--outputs-file', dest='outputs_file', type=optional_string)
    create_environment_parser.set_defaults(func=create_environment)

    delete_deployment_parser = subparsers.add_parser('delete-deployment', parents=[common_parent])
    delete_deployment_parser.add_argument('--name', required=True)
    delete_deployment_parser.set_defaults(func=delete_deployment)

    delete_environment_parser = subparsers.add_parser('delete-environment', parents=[common_parent])
    delete_environment_parser.add_argument('--name', required=True)
    delete_environment_parser.add_argument('--delete-blueprint', type=boolean_string)
    delete_environment_parser.add_argument('--ignore-failure', type=boolean_string)
    delete_environment_parser.set_defaults(func=delete_environment)

    cli_parser = subparsers.add_parser('cli', parents=[common_parent])
    cli_parser.add_argument('--command', required=True)
    cli_parser.add_argument('--set-output', action='store_true', default=False)
    cli_parser.set_defaults(func=cli)

    integrations_parent = argparse.ArgumentParser(add_help=False, parents=[common_parent])
    integrations_parent.add_argument('--name', required=True)
    integrations_parent.add_argument('--invocation-params-file', type=optional_existing_path)
    integrations_parent.add_argument('--outputs-file', type=optional_string)

    terraform_parser = subparsers.add_parser('terraform', parents=[integrations_parent])
    terraform_parser.add_argument('--module', required=True)
    terraform_parser.add_argument('--variables', type=optional_existing_path)
    terraform_parser.add_argument('--environment', type=optional_existing_path)
    terraform_parser.add_argument('--environment-mapping', nargs="*", default=[])
    terraform_parser.set_defaults(func=terraform)

    arm_parser = subparsers.add_parser('arm', parents=[integrations_parent])
    arm_parser.add_argument('--resource-group', required=True)
    arm_parser.add_argument('--template-file', required=True)
    arm_parser.add_argument('--parameters-file', type=optional_existing_path)
    arm_parser.add_argument('--credentials-file', type=optional_existing_path)
    arm_parser.add_argument('--location', type=optional_string)
    arm_parser.set_defaults(func=arm)

    cfn_parser = subparsers.add_parser('cfn', parents=[integrations_parent])
    cfn_parser.add_argument('--stack-name', required=True)
    cfn_parser.add_argument('--template-url', type=optional_string)
    cfn_parser.add_argument('--bucket-name', type=optional_string)
    cfn_parser.add_argument('--resource-name', type=optional_string)
    cfn_parser.add_argument('--template-file', type=optional_existing_path)
    cfn_parser.add_argument('--parameters-file', type=optional_existing_path)
    cfn_parser.add_argument('--credentials-file', type=optional_existing_path)
    cfn_parser.add_argument('--region-name', type=optional_string)
    cfn_parser.set_defaults(func=cfn)

    k8s_parser = subparsers.add_parser('k8s', parents=[integrations_parent])
    k8s_parser.add_argument('--gcp-credentials-file', type=optional_existing_path)
    k8s_parser.add_argument('--token', type=optional_string)
    k8s_parser.add_argument('--token-file', type=optional_existing_path)
    k8s_parser.add_argument('--master-host', required=True)
    k8s_parser.add_argument('--namespace', type=optional_string)
    k8s_parser.add_argument('--app-definition-file', required=True)
    k8s_parser.add_argument('--ca-cert-file', type=optional_existing_path)
    k8s_parser.add_argument('--ssl-cert-file', type=optional_existing_path)
    k8s_parser.add_argument('--ssl-key-file', type=optional_existing_path)
    k8s_parser.add_argument('--skip-ssl-verification', type=boolean_string)
    k8s_parser.add_argument('--other-options-file', type=optional_existing_path)
    k8s_parser.add_argument('--validate-status', type=boolean_string)
    k8s_parser.add_argument('--allow-node-redefinition', type=boolean_string)
    k8s_parser.add_argument('--debug', type=boolean_string)
    k8s_parser.set_defaults(func=kubernetes)

    args = parser.parse_args()
    vars_map = vars(args)

    # GitHub Actions currently don't allow passing environment variables
    # (such as "GITHUB_RUN_ID", which is convenient for uniqueness) as
    # action inputs. Therefore, we allow passing them as templates, and we
    # expand them here.
    if IS_GITHUB:
        for key, value in vars_map.iteritems():
            if value and isinstance(value, str):
                vars_map[key] = Template(value).substitute(os.environ)

    configuration = read_json_or_yaml('/etc/cfyci/config.yaml')
    args.func(configuration=configuration, **vars_map)


if __name__ == '__main__':
    main()
