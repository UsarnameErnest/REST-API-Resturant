### Objective

Your assignment is to implement a REST API for a restaurant.

### Brief

Frogo Baggins, a hobbit from the Shire, has a great idea. He wants to build a restaurant that serves traditional dishes from the world of Middle Earth. The restaurant will be called "The Dancing Pony" and will have a cozy atmosphere.

Frogo has hired you to build the website for his restaurant. As payment, he has offered you either a chest of gold or a ring. Choose wisely.

### Tasks (Specifications)

Deliver a REST API which meets the following requirements:

All functionality of the API must require a logged in user.

Users of the system must be able to register and login.
- At a minimum, the system should support password based authentication.
- Users must always have a name and email

The API needs authorization support for two roles, namely Administrators, and Customers.

Adminstrators must be able to take the following actions:
- Create, View, List, Update, and Delete dishes
- Dishes must always have a name, description, price, and image

Customers must be able to take the following actions:
- Search, View, and Rate dishes
- A dish can only be rated once per customer, and the rating can be updated.

#### Looking for more of a challenge?

If this was all a bit basic, then perhaps you can consider flexing by meeting some of the following bonus requirements:

- To prevent abuse, the API must have rate-limiting per logged in customer
- Allow users to login using OAuth2 based SSO (Google, etc)
- Allow multiple different restaurants to use the product (multi-tenant SaaS)

#### Constraints

- Implement the assignment using any language.
- Implement a REST API utilizing JSON for request and response bodies where applicable.

#### Tips, Advice, Guidance

- Your are encouraged to make use of a web framework, sql ORM, etc. This will help reduce the overhead of writing boilerplate code, and will let you focus on the core requirements.
- You are welcome to make use of AI to help write the code.
- This assessment is open ended, and candidates could spend weeks crafting the perfect API. We encourage you to timebox yourself, and limit the amount of time you spend. When we talk through the assessment, this can be provided as an input, and it is good to talk about the trade-offs made given the time constraint. We recommend about 6-8 hours of focused time.
- This assessment is used for Juniors and Seniors.
  - For junior candidates, start simple and focus on the more approachable code segments first. It's ok to not meet all the requirements.
  - For intermeidate and senior candidates, the expectations are higher, and the solution needs to reflect your capabilities as an intermediate/senior.

### Evaluation Criteria

The test will be evaluated based on functional and non-functional requirements.

For functional requirements, your API needs to work, and meet all the requirements as provided.

For non-functional requirements, your API needs to be production-ready to a reasonable extent. We
are looking for adherence to qualities such as testability, maintainability, observability, and security.

### Supporting Assets

You've been provided with a docker-compose file which will bring up a postgres database and prometheus. These are optional and provided to help get started.

#### Postgres

You can connect to the database via localhost:5432 using the username and password configured in the docker-compose.yml.

#### Prometheus

You can configure prometheus via the provided prometheus.yml file.

### CodeSubmit

Please organize, design, test, and document your code as if it were going into production - then push your changes to the master branch. After you have pushed your code, you may submit the assignment on the assignment page.

Best of luck, and happy coding!

The Bash Team
