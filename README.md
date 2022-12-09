# 426project-jiangzc210
Express api that handles login and other user operations. 
To start the app, enter ``npm start`` in the terminal.
## Handles
**Note:** POST handles accepts data in ``x-www-form-urlencoded`` format.

### POST /app/user/new
Creates a new user in the database. Requires parameter ``Username``, ``Email``, and ``Password`` in the body.

### POST /app/user/login
Change the user status to logged in. Requires parameter ``Username`` and ``Password`` in the body.

### POST /app/user/update:username
Update the account information of the corresponding ``username`` to the data provided in request body. Requires parameter ``OldPassword``, ``Email``, and ``Password`` in the body where ``OldPassword`` is required for authentication purposes.

### POST /app/user/delete:username
Delete the account information of the corresponding ``username``. Required parameter ``Passowrd`` in the body.

### GET /app/user/info:username
Returns a ``JSON`` containing the ``Email`` of the user.

### GET /app/user/login
Returns a ``JSON`` showing whether the user is logged in.
