import sys
import os
import subprocess
import pyautogui
import multiprocessing

from time import time, sleep
import webbrowser
import boto3
from boto3.session import Session

region = "eu-west-1"


def find_and_press_8():
    num_processes = 8
    pool = multiprocessing.Pool(processes=num_processes)
    args = range(num_processes)
    pool.map(find_and_press, args)
    pool.close()
    pool.join()


def find_and_press(arg):
    # Locate and click on the email address field
    email_field_location = pyautogui.locateOnScreen("Login.PNG")
    if email_field_location:
        email_field_center = pyautogui.center(email_field_location)
        pyautogui.click(email_field_center)

        # Wait for the email field to be selected
        sleep(2)

    # Locate and click on the Allow button
    allow_button_location = pyautogui.locateOnScreen("Allow.png")
    if allow_button_location:
        allow_button_center = pyautogui.center(allow_button_location)
        pyautogui.click(allow_button_center)

        # Wait for the Allow button to be clicked
        sleep(2)


def listAccounts(found_token, sso, sso_token):
    if found_token:
        accounts = sso.list_accounts(nextToken=found_token, accessToken=sso_token)
    else:
        accounts = sso.list_accounts(accessToken=sso_token)
    return accounts


def ssoListAccounts(sso, sso_token):
    records = []
    more_objects = True
    found_token = ""
    while more_objects:
        accounts = listAccounts(found_token, sso, sso_token)
        for account in accounts["accountList"]:
            if "accountId" in account:
                records.append(account["accountId"])

        # Now check there is more objects to list
        if "nextToken" in accounts:
            found_token = accounts["nextToken"]
            more_objects = True
        else:
            break
    return records


def listAcctRoles(found_token, sso, sso_token, accountId):
    if found_token:
        roles_response = sso.list_account_roles(
            nextToken=found_token, accessToken=sso_token, accountId=accountId
        )
    else:
        roles_response = sso.list_account_roles(
            accessToken=sso_token, accountId=accountId
        )
    return roles_response


def ssoListAccountRoles(sso, sso_token, accountId):
    records = []
    more_objects = True
    found_token = ""
    while more_objects:
        accountRoles = listAcctRoles(found_token, sso, sso_token, accountId)
        for accountRole in accountRoles["roleList"]:
            if "roleName" in accountRole:
                records.append(accountRole["roleName"])

        # Now check there is more objects to list
        if "nextToken" in accountRoles:
            found_token = accountRoles["nextToken"]
            more_objects = True
        else:
            break
    return records


def run_app_with_aws_secrets(access_id, access_secret, access_session, command):
    new_env = os.environ.copy()

    new_env["AWS_ACCESS_KEY_ID"] = access_id
    new_env["AWS_SECRET_ACCESS_KEY"] = access_secret
    new_env["AWS_SESSION_TOKEN"] = access_session

    subprocess.run([command], env=new_env, shell=True)


def aws_login(start_url, account_id, role_id, command):
    session = Session()
    sso_oidc = session.client("sso-oidc")
    client_creds = sso_oidc.register_client(
        clientName="myapp",
        clientType="public",
    )
    device_authorization = sso_oidc.start_device_authorization(
        clientId=client_creds["clientId"],
        clientSecret=client_creds["clientSecret"],
        startUrl=start_url,
    )
    url = device_authorization["verificationUriComplete"]
    device_code = device_authorization["deviceCode"]
    expires_in = device_authorization["expiresIn"]
    interval = device_authorization["interval"]
    webbrowser.open(url, autoraise=True)
    for n in range(1, expires_in // interval + 1):
        sleep(interval)
        try:
            find_and_press_8()

            token = sso_oidc.create_token(
                grantType="urn:ietf:params:oauth:grant-type:device_code",
                deviceCode=device_code,
                clientId=client_creds["clientId"],
                clientSecret=client_creds["clientSecret"],
            )
            break
        except sso_oidc.exceptions.AuthorizationPendingException:
            pass
    sso = boto3.client("sso", region_name=region)
    sso_token = token.get("accessToken")
    listAccounts = ssoListAccounts(sso, sso_token)
    for accountId in listAccounts:
        if accountId == account_id:
            listAcctRoles = ssoListAccountRoles(sso, sso_token, accountId)
            for roleId in listAcctRoles:
                if roleId == role_id:
                    sts_credentials = sso.get_role_credentials(
                        accessToken=sso_token, accountId=accountId, roleName=roleId
                    )

                    aws_access_key_id = sts_credentials["roleCredentials"][
                        "accessKeyId"
                    ]
                    aws_secret_access_key = sts_credentials["roleCredentials"][
                        "secretAccessKey"
                    ]
                    aws_session_token = sts_credentials["roleCredentials"][
                        "sessionToken"
                    ]

                    run_app_with_aws_secrets(
                        aws_access_key_id,
                        aws_secret_access_key,
                        aws_session_token,
                        command,
                    )


def main():
    print("AWS Auto login v1.1")
    aws_login(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])


if __name__ == "__main__":
    main()
