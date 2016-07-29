#!/usr/bin/env python
from __future__ import print_function, unicode_literals

import collections
import io
import json
import os.path
import string

import boto3
import botocore

# Constants
EXTERNAL_ID_CHARACTERS = string.ascii_lowercase + string.digits + '-'

OBSERVABLE_POLICY_NAME = 'observableNetworksPolicy'
OBSERVABLE_POLICY_DESCRIPTION = (
    'Grants Observable Networks read access to resources'
)
OBSERVABLE_ROLE_NAME = 'observableNetworksRole'

FLOWLOGS_POLICY_NAME = 'flowlogsPolicy'
FLOWLOGS_POLICY_DESCRIPTION = (
    'Grants VPC Flow Logs write access to CloudWatch Logs'
)
FLOWLOGS_ROLE_NAME = 'flowlogsRole'
FLOWLOGS_GROUP_NAME = 'flowlogsGroup'


# Known AWS regions
AWS_REGIONS = {
    'us-east-1',
    'us-west-1',
    'us-west-2',
    'eu-west-1',
    'eu-central-1',
    'ap-northeast-1',
    'ap-northeast-2',
    'ap-southeast-1',
    'ap-southeast-2',
    'sa-east-1',
}


class OnSetup(object):
    def __init__(self, base_path, **kwargs):
        self.base_path = base_path

        boto_kwargs = {}
        if kwargs['profile_name']:
            boto_kwargs['profile_name'] = kwargs['profile_name']
        elif kwargs['aws_access_key_id'] and kwargs['aws_access_key_id']:
            boto_kwargs['aws_access_key_id'] = args.aws_access_key_id
            boto_kwargs['aws_secret_access_key'] = args.aws_secret_access_key

        self.boto_session = boto3.session.Session(**boto_kwargs)
        if not self.boto_session.get_credentials():
            raise Exception('Missing AWS credentials.')
        self.iam_client = self.boto_session.client('iam')

    def _get_policy_dict(self, file_name):
        file_path = os.path.join(self.base_path, file_name)
        with io.open(file_path, 'r') as infile:
            D_policy = json.load(infile)

        return D_policy

    def _create_policy(self, policy_name, policy_dict, policy_description):
        policy_document = json.dumps(policy_dict, indent=4)
        policy_resp = self.iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=policy_document,
            Description=policy_description
        )
        policy_arn = policy_resp['Policy']['Arn']

        return policy_arn

    def _create_role(self, role_name, role_dict):
        policy_document = json.dumps(role_dict, indent=4)
        role_resp = self.iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=policy_document,
        )
        role_arn = role_resp['Role']['Arn']

        return role_arn

    def _attach_policy(self, role_name, policy_arn):
        self.iam_client.attach_role_policy(
            RoleName=role_name, PolicyArn=policy_arn
        )

    def set_observable_access(self, external_id):
        # Create the policy
        policy_dict = self._get_policy_dict('obsrvbl-policy.json')
        policy_arn = self._create_policy(
            OBSERVABLE_POLICY_NAME,
            policy_dict,
            OBSERVABLE_POLICY_DESCRIPTION
        )

        # Create the role
        trust_dict = self._get_policy_dict('obsrvbl-trust.json')
        (
            trust_dict['Statement'][0]
            ['Condition']['StringEquals']['sts:ExternalId']
        ) = external_id
        role_arn = self._create_role(OBSERVABLE_ROLE_NAME, trust_dict)

        # Attach the policy to the role
        self._attach_policy(OBSERVABLE_ROLE_NAME, policy_arn)
        return role_arn

    def set_flowlogs_access(self):
        # Create the policy
        policy_dict = self._get_policy_dict('flowlogs-policy.json')
        policy_arn = self._create_policy(
            FLOWLOGS_POLICY_NAME,
            policy_dict,
            FLOWLOGS_POLICY_DESCRIPTION
        )

        # Create the role
        trust_dict = self._get_policy_dict('flowlogs-trust.json')
        role_arn = self._create_role(FLOWLOGS_ROLE_NAME, trust_dict)

        # Attach the policy to the role
        self._attach_policy(FLOWLOGS_ROLE_NAME, policy_arn)

        return role_arn

    def get_vpc_status(self, region_name):
        ec2_client = self.boto_session.client('ec2', region_name=region_name)

        resp = ec2_client.describe_vpcs()
        all_vpcs = {item['VpcId'] for item in resp.get('Vpcs', [])}

        resp = ec2_client.describe_flow_logs()
        ret = dict.fromkeys(all_vpcs)
        for item in resp.get('FlowLogs', []):
            resource_id = item['ResourceId']
            if resource_id not in all_vpcs:
                continue
            ret[resource_id] = item['LogGroupName']

        return ret

    def create_log_group(self, region_name, log_group_name):
        logs_client = self.boto_session.client('logs', region_name=region_name)

        try:
            logs_client.create_log_group(logGroupName=log_group_name)
        except botocore.exceptions.ClientError:
            print(
                "Couldn't create log group {} in region {}".format(
                    log_group_name, region_name
                )
            )
            return

        logs_client.put_retention_policy(
            logGroupName=log_group_name, retentionInDays=1
        )

    def create_flow_logs(self, region_name, vpc_id, role_arn):
        ec2_client = self.boto_session.client('ec2', region_name=region_name)

        print(
            'Logging vpc {} to {} in {}'.format(
                vpc_id, FLOWLOGS_GROUP_NAME, region_name
            )
        )
        try:
            ec2_client.create_flow_logs(
                ResourceIds=[vpc_id],
                ResourceType='VPC',
                TrafficType='ALL',
                LogGroupName=FLOWLOGS_GROUP_NAME,
                DeliverLogsPermissionArn=role_arn,
            )
        except botocore.exceptions.ClientError:
            print(
                "Couldn't create log group {} in region {} for vpc {}".format(
                    FLOWLOGS_GROUP_NAME, region_name, vpc_id
                )
            )
            return

    def get_role_arn(self, role_name):
        try:
            resp = self.iam_client.get_role(RoleName=role_name)
        except botocore.exceptions.ClientError:
            return None
        else:
            return resp['Role']['Arn']


def main(base_path, args):
    on_setup = OnSetup(
        base_path,
        profile_name=args.profile_name,
        aws_access_key_id=args.aws_access_key_id,
        aws_secret_access_key=args.aws_secret_access_key,
    )

    print(
        ' __   __   __   ___  __             __        ___ \n'
        '/  \ |__) /__` |__  |__) \  /  /\  |__) |    |__  \n'
        '\__/ |__) .__/ |___ |  \  \/  /~~\ |__) |___ |___ \n'
        '      ___ ___       __   __        __             \n'
        '|\ | |__   |  |  | /  \ |__) |__/ /__`            \n'
        '| \| |___  |  |/\| \__/ |  \ |  \ .__/            \n'
    )

    print(
        "What Observable Networks web portal will you use? "
        "If it will be example.obsrvbl.com then type example."
    )
    external_id = ''
    while True:
        external_id = raw_input('External ID: ')
        if not external_id:
            continue
        elif any(c not in EXTERNAL_ID_CHARACTERS for c in external_id):
            print('External ID must be lowercase ASCII only')
        elif len(external_id) > 16:
            print('External ID must 16 letters or fewer')
        else:
            break

    observable_policy_dict = on_setup._get_policy_dict('obsrvbl-policy.json')
    observable_policy_document = json.dumps(observable_policy_dict, indent=4)
    print("The role for cross-account access will use this policy:")
    print(observable_policy_document)

    should_create_observable_role = ''
    while True:
        should_create_observable_role = raw_input(
            'Create cross-account role? (yes/no): '
        )
        if should_create_observable_role == 'yes':
            should_create_observable_role = True
            break
        elif should_create_observable_role == 'no':
            should_create_observable_role = False
            break

    vpcs_needing_logs = collections.defaultdict(set)
    print('Check a region for VPC flows?')
    while True:
        region_name = 'us-east-1'
        while True:
            region_name = raw_input('AWS region (us-east-1): ') or region_name
            if region_name in AWS_REGIONS:
                break
            else:
                print('Invalid region {}'.format(region_name))

        vpc_status = on_setup.get_vpc_status(region_name)
        print()
        print('AWS region', 'VPC ID', 'Flow Logs group', sep='\t')
        for vpc_id, log_group_name in vpc_status.items():
            print(region_name, vpc_id, log_group_name, sep='\t')
        print()

        print(
            "For which VPCs should log groups be created? "
            "Note that AWS charges for log storage."
        )
        target_vpc = ''
        while True:
            target_vpc = raw_input(
                'Create group for (VPC ID/all/none/missing): '
            )
            if (target_vpc == '') or (target_vpc == 'none'):
                break
            elif target_vpc == 'all':
                vpcs_needing_logs[region_name].update(vpc_status.keys())
                break
            elif target_vpc == 'missing':
                missing = {k for k, v in vpc_status.iteritems() if v is None}
                vpcs_needing_logs[region_name].update(missing)
                break
            elif target_vpc not in vpc_status:
                print('Unrecognized VPC {}'.format(target_vpc))
            else:
                vpcs_needing_logs[region_name].add(target_vpc)

        check_another_region = raw_input('Check another region? (no): ')
        check_another_region = check_another_region or 'no'
        if check_another_region == 'no':
            break

    should_create_flowlogs_role = False
    if vpcs_needing_logs:
        flowlogs_role_arn = on_setup.get_role_arn(FLOWLOGS_ROLE_NAME)
        if not flowlogs_role_arn:
            print("Couldn't find {} role".format(FLOWLOGS_ROLE_NAME))
            should_create_flowlogs_role = ''
            while True:
                should_create_flowlogs_role = raw_input(
                    'Create {} role? (yes/no): '.format(FLOWLOGS_ROLE_NAME)
                )
                if should_create_flowlogs_role == 'yes':
                    should_create_flowlogs_role = True
                    break
                elif should_create_flowlogs_role == 'no':
                    should_create_flowlogs_role = False
                    break

    print()
    should_write = ''
    while True:
        should_write = raw_input(
            'Make the requested changes? (yes/no): '
        )
        if should_write == 'yes':
            break
        elif should_write == 'no':
            print('Exiting.')
            return

    # Do the stuff
    print()
    observable_role_arn = ''
    if should_create_observable_role:
        print('Creating {} role'.format(OBSERVABLE_ROLE_NAME))
        try:
            observable_role_arn = on_setup.set_observable_access(external_id)
        except botocore.exceptions.ClientError:
            print(
                "Error creating {} role. Perhaps it already exists?".format(
                    OBSERVABLE_ROLE_NAME
                )
            )

    if should_create_flowlogs_role:
        print('Creating {} role'.format(FLOWLOGS_ROLE_NAME))
        flowlogs_role_arn = on_setup.set_flowlogs_access()

    for region_name in vpcs_needing_logs.keys():
        region_vpcs = vpcs_needing_logs[region_name]
        if not region_vpcs:
            continue
        print(
            'Creating log group {} in region {}'.format(
                FLOWLOGS_GROUP_NAME, region_name
            )
        )
        on_setup.create_log_group(region_name, FLOWLOGS_GROUP_NAME)
        for vpc_id in vpcs_needing_logs[region_name]:
            on_setup.create_flow_logs(region_name, vpc_id, flowlogs_role_arn)

    print()
    if should_create_observable_role and observable_role_arn:
        print(
            "All finished. Copy the Role ARN below to enter into the "
            "Observable web portal:"
        )
        print(observable_role_arn)
    elif should_create_observable_role and not observable_role_arn:
        print(
            "Couldn't create the Observable Role. Contact "
            "support@observable.net for assistance."
        )

    print()
    print(
        'Take note of any log groups above; you will enter them into the '
        'Observable web portal.'
    )

if __name__ == '__main__':
    from argparse import ArgumentParser

    argument_parser = ArgumentParser()
    argument_parser.add_argument(
        '--aws-access-key-id', help='AWS access key ID',
    )
    argument_parser.add_argument(
        '--aws-secret-access-key', help='AWS secret access key',
    )
    argument_parser.add_argument(
        '--profile-name', help='AWS profile name',
    )
    args = argument_parser.parse_args()

    base_path = os.path.dirname(os.path.abspath(__file__))

    try:
        main(base_path, args)
    except Exception as e:
        print(e)
