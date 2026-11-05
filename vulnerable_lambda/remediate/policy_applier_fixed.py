# policy_applier_lambda — REMEDIATED
#
# Root-cause fix for the CloudGoat `vulnerable_lambda` scenario.
# The original built a SQL string by f-string-interpolating caller input
# directly into the WHERE clause, so a payload like  AdministratorAccess' --
# could comment out the  public='True'  guard and apply a non-public policy.
#
# Fix: use a BOUND PARAMETER (:policy). Caller input is now passed as a value,
# never as SQL syntax, so it cannot close the string or comment out the guard.
# Defense in depth: an explicit allowlist check before the query.

import boto3
from sqlite_utils import Database

db = Database("my_database.db")
iam_client = boto3.client('iam')

# Only these managed policies may ever be self-applied.
APPROVED_POLICIES = {
    "AmazonSNSReadOnlyAccess",
    "AmazonRDSReadOnlyAccess",
    "AWSLambda_ReadOnlyAccess",
    "AmazonS3ReadOnlyAccess",
    "AmazonGlacierReadOnlyAccess",
    "AmazonRoute53DomainsReadOnlyAccess",
}


def handler(event, context):
    target_policies = event['policy_names']
    user_name = event['user_name']

    for policy in target_policies:
        # Defense in depth: reject anything not on the allowlist outright.
        if policy not in APPROVED_POLICIES:
            msg = f"{policy} is not an approved policy. Request denied."
            print(msg)
            return msg

        # Parameterized query: `policy` is bound as a value, not SQL text,
        # so `' --` injection cannot escape the string or drop the guard.
        statement = "select policy_name from policies " \
                    "where policy_name = :policy and public = 'True'"

        applied = False
        for row in db.query(statement, {"policy": policy}):
            applied = True
            print(f"applying {row['policy_name']} to {user_name}")
            resp = iam_client.attach_user_policy(
                UserName=user_name,
                PolicyArn=f"arn:aws:iam::aws:policy/{row['policy_name']}"
            )
            print("result: " + str(resp['ResponseMetadata']['HTTPStatusCode']))

        if not applied:
            msg = f"{policy} is not an approved policy, request denied."
            print(msg)
            return msg

    return "All managed policies were applied as expected."
