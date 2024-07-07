# 2.6.0

Add permissions to user object and pass that into the tokens.

# 2.5.1

Remove deprecated jjwt functions.

# 2.5.0

Now using the most up to date micronaut and jjwt library

# 2.4.0

Updated dependencies to use deploy and unit test events.

# 2.3.0cd ..

Updated dependencies

# 2.2.0

Major refactor. Multi tenancy now works for all user and app functions. The app no longer needs a rotating/expiring internal token for emailing.

# 2.1.0

Several bug fixes to support multi tenancy.

# 2.0.0

Support multi tenancy for users and apps. Allow for auto-registration of users in other tenants. Upgrade micronaut version.

# 1.5.0

Added better error handling and added a /user/me endpoint. Upgraded to micronaut 4.

# 1.4.1

Add additional validation checks on internal tokens

# 1.4.0

Allow creation of internal tokens

# 1.3.0

Add `tenant_admin` role and update dependencies. Utilize micronaut beans for the datastore client.

# 1.2.0

Enable multi-tenancy by adding a tenant to users. The tenant is encoded within the JWT. 

# 1.1.0

Enforce HTTPS only and improve test coverage

# 1.0.0

Update to Micronaut and Java 17

# 0.9.2

Fixed bug with refresh tokens

# 0.9.1

Use improved datastore client

# 0.9.0

Move to github actions. Lazy load properties. Remove eventhub-client in favor of a reactions-client.

# 0.8.1

Updated dependencies

# 0.8.0

Optimized the getIdentity methods by using a filter instead of retrieving all

# 0.7.0

Provides utilities for users and tokens on Trevorism
