Feature: Adding a new tenant users
  Create a new identity, a user, with a username and password. The user can securely access resources within its tenant

  Scenario: Register a new user
    Given the auth application is alive
    And the auth test tenant is registered
    And an auth test tenant admin user is registered
    When an user is successfully registered and is active
    Then the user is valid
    And the user is cleaned up afterwards

  Scenario: A user can obtain a token
    Given the auth application is alive
    And the auth test tenant is registered
    And an auth test tenant admin user is registered
    And an user is successfully registered and is active
    When an user requests a token
    Then a token is successfully obtained
    And the token is well formed
    And the user is cleaned up afterwards