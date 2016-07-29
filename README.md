# Observable Networks setup tool

The script in this repository will help you add the necessary AWS configuration to allow Observable Networks to read VPC Flow Logs and resource metadata from your account.

In a hurry? Run `onsetup.py` with your AWS credentials in your environment and follow the prompts.

## Starting the wizard

Make sure you're got your AWS API key information available.
If you have [AWS environment variables](http://boto3.readthedocs.io/en/latest/guide/configuration.html#environment-variables) set, simply switch to the project directory and run this command:
```bash
python onsetup.py
```

Otherwise, specify your key information when invoking the script:
```bash
python onsetup.py \
    --aws-access-key-id="ASDFQWERZXCVGHJKTYUI" \
    --aws-secret-access-key="o7HxTNWpNb2cSNVV94MfIVBAKe5yKIRITMuIaQlf" \
```

The `--profile` switch lets you specify [named AWS profile](http://boto3.readthedocs.io/en/latest/guide/configuration.html#shared-credentials-file) instead of the access keys.

## Answering the prompts

When you run `onsetup.py` you'll be asked a series of questions:
* Whether to create the Observable role for cross-account access
* Whether to create log groups for VPCs that don't have them already
* Whether to create a role for AWS to use when saving VPC Flow Logs to CloudWatch Logs

To use the Observable service you'll at least need to create the role and have one log group with VPC flow logs.

Once you're finished, copy down the role ARN and make note of which VPC Flow Log groups you want to monitor.

## Other notes

You may review the policy documents included here.
The permissions are requested to allow Observable to match data from your AWS account to the network traffic in VPC Flow Logs.
You may narrow down the permissions if needed. For example, you may want to change the policy document to allow read access to only certain log groups.

The script is meant to be run once, and doesn't go out of its way to do error handling.
If you have questions or problems please e-mail support@obsrvbl.com.
