from __future__ import annotations

import json
import logging
from typing import Any
from typing import cast
from typing import TYPE_CHECKING

import boto3
from app_config import AppSecrets
from dynamodb_json import json_util as ddb_json  # type: ignore
from models.aws import DynamoDBAtomicOp

if TYPE_CHECKING:
    from mypy_boto3_dynamodb import DynamoDBClient
    from mypy_boto3_secretsmanager import SecretsManagerClient

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app_secrets = AppSecrets()

class AWSClientResourceFactory:
    def __init__(self) -> None:
        self._session: boto3.Session | None = None
        self._ddb: DynamoDBClient | None = None
        self._secrets: SecretsManagerClient | None = None

    @property
    def session(self):
        if not self._session:
            self._session = boto3.Session(region_name=app_secrets.AWS_REGION)

        return self._session

    @property
    def ddb(self):
        if not self._ddb:
            self._ddb = self.session.client('dynamodb')

        return self._ddb

    @property
    def app_secrets(self):
        if not self._secrets:
            self._secrets = self.session.client('secretsmanager')

        return self._secrets

    def reset(self):
        self._session = None
        self._ddb = None
        self._secrets = None


_aws = AWSClientResourceFactory()


class MissingPrimaryKeyError(ValueError):
    def __init__(self, username: str) -> None:
        super().__init__(f'item is missing the primary key "{username}"')


class DynamoDB:
    """Provides higher-level functions to interact with DynamoDB"""

    def __init__(self, tablename: str, username: str) -> None:
        self.tablename = tablename
        self.pk = username

    def get(self, username: str) -> dict[str, Any] | None:
        """Gets a single item by primary key"""
        data = _aws.ddb.get_item(
            TableName=self.tablename, Key={
                self.pk: {'S': username},
            },
        )
        if 'Item' not in data:
            return None

        return ddb_json.loads(data['Item'])

    def query(self, index: str, value: str) -> list[dict[str, Any]]:
        """Queries by global secondary index and returns all items"""

        key_condition_expression = f'{index} = :{index}'
        expression_attribute_values = {f':{index}': {'S': value}}

        data = _aws.ddb.query(
            TableName=self.tablename,
            IndexName=index,
            KeyConditionExpression=key_condition_expression,
            ExpressionAttributeValues=expression_attribute_values,
        )

        if 'Items' not in data:
            return []

        return ddb_json.loads(data['Items'])

    def put(self, item: dict[str, Any], allow_update=True) -> None:

        # <-- Log the username using the logging framework
        logger.debug('...................Item[]: %s', item)

        """Creates or updates a single item"""

        if self.pk not in item:
            raise MissingPrimaryKeyError(self.pk)
        
        ddb_data = ddb_json.dumps(item, as_dict=True)
        logger.debug("...............DynamoDB JSON Payload: %s", json.dumps(ddb_data, indent=2))

        if allow_update:
            _aws.ddb.put_item(
                TableName=self.tablename,
                Item=ddb_json.dumps(item, as_dict=True),
            )

        else:
            _aws.ddb.put_item(
                TableName=self.tablename,
                Item=ddb_json.dumps(item, as_dict=True),
                ConditionExpression=f'attribute_not_exists({self.pk})',
            )

    def atomic_op(
        self, username_value: str, attribute: str, attribute_change_value: int, op: DynamoDBAtomicOp,
    ) -> int:
        """Performs an atomic operation"""

        # nested attributes are separated by dots, so we need to break them out and parameterize them
        attr_components = attribute.split('.')
        ex_attribute_names = {
            f'#attribute{i}': attr for i,
            attr in enumerate(attr_components)
        }
        ex_attribute_values = {':dif': {'N': str(attribute_change_value)}}

        # ex: "counters.likes = 0"
        if op == DynamoDBAtomicOp.overwrite:
            ex_equals = ':dif'

        # ex: "counters.likes = counters.likes + 1"
        else:
            ex_equals = f"{'.'.join(ex_attribute_names)} {op.value} :dif"

        expression = f"SET {'.'.join(ex_attribute_names)} = {ex_equals}"

        response_data = _aws.ddb.update_item(
            TableName=self.tablename,
            Key={self.pk: {'S': username_value}},
            ExpressionAttributeNames=ex_attribute_names,
            ExpressionAttributeValues=ex_attribute_values,
            UpdateExpression=expression,
            ReturnValues='UPDATED_NEW',
        )

        data: dict | int = ddb_json.loads(response_data['Attributes'])
        data = cast(dict, data)

        # we need to unpack the data to get the final nested key, so we recursively drill-down into the data
        for attr_component in attr_components:
            data = data.pop(attr_component)
            if isinstance(data, int):
                return data

        logging.error(
            'Reached end of nested atomic op; this should never happen!',
        )
        logging.error(f'Looking for value of: {attribute}')
        logging.error(f'Response: {response_data}')
        raise Exception('Invalid response from DynamoDB')

    def delete(self, username_value: str) -> None:
        """Deletes one item by primary key"""

        _aws.ddb.delete_item(
            TableName=self.tablename, Key={
                self.pk: {'S': username_value},
            },
        )
        return


class SecretsManager:
    @staticmethod
    def get_secrets(secret_id: str) -> dict[str, Any]:
        logger.debug('....................GET_SECRETS: %s', secret_id)
        """Fetches app_secrets from AWS app_secrets manager"""

        response = _aws.app_secrets.get_secret_value(SecretId=secret_id)
        logger.debug('....................GET_SECRETS RESPONSE: %s', response)
        return json.loads(response['SecretString'])


class SQSFIFO:
    """Provides higher-level functions to interact with SQS FIFO queues"""

    def __init__(self, queue_url: str) -> None:
        self.queue = _aws.sqs.Queue(queue_url)

    def send_message(self, content: str, de_dupe_id: str, group_id: str) -> None:
        self.queue.send_message(
            MessageBody=content,
            MessageDeduplicationId=de_dupe_id,
            MessageGroupId=group_id,
        )