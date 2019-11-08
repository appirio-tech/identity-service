## POST /v3/groups
An endpoint to create a group.

##### Headers
- Content-Type: application-json
- Authorization: Bearer [JWT]

##### Body Example
    {
      "param": {
        "name": "ExampleGroup",
        "description": "This is an example group."
      }
    }

## PUT /v3/groups/{groupId}

An endpoint to update a group.

##### Headers

- Content-Type: application-json
- Authorization: Bearer [JWT]

##### Parameters

- groupId (number, required): ID of the group to be updated.

##### Body Example

```
{
  "param": {
    "name": "ExampleGroup",
    "description": "This is an example group."
  }
}
```

## GET /v3/groups/{groupId}

An endpoint to get a group.

##### Headers

- Authorization: Bearer [JWT]

##### Parameters

- groupId (number, required): ID of the group to be retrieved.

## DELETE /v3/groups/{groupId}

An endpoint to delete a group.

##### Headers

- Authorization: Bearer [JWT]

##### Parameters

- groupId (number, required): ID of the group to be deleted.

## GET /v3/groups?memberId={memberId}&membershipType={membershipType}

An endpoint to query groups which the specified member belongs to.

##### Headers
- Authorization: Bearer [JWT]

##### Parameters
- memberId (number, optional): ID of the member which belongs to groups to be searched.
- membershipType (number, optional): Membership type of the member specified in memberId.


## POST /v3/groups/{groupId}/members
An endpoint to add a member to group.

##### Headers
- Content-Type: application-json
- Authorization: Bearer [JWT]

##### Parameters
- groupId (number, required): ID of the group

##### Body Example
    {
      "param": {
        "memberId": "40097676",
        "membershipType": "user"
      }
    }

## GET /v3/groups/{groupId}/members

An endpoint to get members of a group.

##### Headers

- Authorization: Bearer [JWT]

##### Parameters

- groupId (number, required): ID of the group



## DELETE /v3/groups/{groupId}/members/{membershipId}

An endpoint to remove a member from group.

##### Headers
- Authorization: Bearer [JWT]

##### Parameters
- groupId (number, required): ID of the group
- membershipId (number, required) - ID of the membership
