## Verify get sub groups

### Setup

- Follow folder **docker/README.md** to setup the environment.
- Execute the following sql against the mysql database(Authorization):
- Execute the following sql against the informix database(common_oltp)

delete from user_sso_login where user_id in (1111, 2222);

delete from user where user_id in (1111, 2222);

insert into user (user_id, first_name, last_name, status, handle) values (1111, 'first 1', 'last 1', 'Active', 'heffan');

insert into user (user_id, first_name, last_name, status, handle) values (2222, 'first 2', 'last 2', 'Active', 'heffan2');

### Verify
Import the `doc/groups` `api.postman_collection.json` into the `postman`, select `Service API Enhancement` folder and check each api.

For instance:
`create or update user sso login record`

The response is:
```json
{
    "id": "26a88cec:161e9f08d1a:-7ffc",
    "result": {
        "success": true,
        "status": 200,
        "metadata": null,
        "content": {
            "userId": "externalUserId",
            "name": "first 3 last 3",
            "email": "heffan@tc.com",
            "providerType": null,
            "provider": "okta-customer",
            "context": null,
            "social": false,
            "enterprise": false,
            "emailVerified": false
        }
    },
    "version": "v3"
}
```
`update user sso login record`

The response is:
```json
{
    "id": "26a88cec:161e9f08d1a:-7ff9",
    "result": {
        "success": true,
        "status": 200,
        "metadata": null,
        "content": {
            "userId": "externalUserId",
            "name": "first 3 last 3",
            "email": "heffan@tc.com",
            "providerType": null,
            "provider": "okta-customer",
            "context": null,
            "social": false,
            "enterprise": false,
            "emailVerified": false
        }
    },
    "version": "v3"
}
```

After create the user sso login record with two providers `sfdc-aspdev` and `okta-customer`, 
you can check `get user sso identifies by user id`, the response is:
```json
{
    "id": "26a88cec:161e9f08d1a:-7ff0",
    "result": {
        "success": true,
        "status": 200,
        "metadata": null,
        "content": [
            {
                "userId": "externalUserId",
                "name": "first 3 last 3",
                "email": "heffan@tc.com",
                "providerType": "samlp",
                "provider": "okta-customer",
                "context": null,
                "social": false,
                "enterprise": true,
                "emailVerified": false
            },
            {
                "userId": "externalUserId",
                "name": "first 3 last 3",
                "email": "heffan@tc.com",
                "providerType": "samlp",
                "provider": "sfdc-aspdev",
                "context": null,
                "social": false,
                "enterprise": true,
                "emailVerified": false
            }
        ]
    },
    "version": "v3"
}
```
