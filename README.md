>**Michael:** Well, I’ll tell you what. I’m going to give you a promotion. Welcome aboard, Mr. Manager.
>
>**George Michael:** Wow. I’m Mr. Manager!
>
>**Michael:** Well, manager; we just say manager.

_It's up to you -- you're the manager now!_

# mrmanager

`mrmanager` is a tool we use internally to get credentials and write them to the correct place. It's a UI wrapper around Vault. It was one of our first golang tools here at Threat Stack. `mrmanager` has opinions about the way you set up Vault and your infrastructure:

* You have Vault configured to give you AWS tokens - either at `aws/` (default) or `aws-envname/` (`-e` flag with `mrmanager aws`).
* You have Vault configured to give you database credentials using the `database/` endpoint, and you name all your roles `dbname-rolename` with `readonly` being a good default role. Additionally, your database uses standard ports; 5432 for PostgreSQL and 3306 for MySQL
* You use the Duo MFA integration 
  * For Vault versions _before_ version 1.11, you use the legacy MFA API
  * For Vault versions versions 1.11 and later you've configured [Login MFA](https://developer.hashicorp.com/vault/docs/auth/login-mfa)

## How can I use it?
Setting up vault is outside the scope of this tool's documentation, but fortunately [Vault](https://www.vaultproject.io/docs/)'s documentation is decent.

You will likely need to make modifications to `mrmanager` to fit your environment. We chose to open-source this because having this template is a handy start to ease your fellow engineers and users into generating limited-time tokens for databases and AWS.

Ensure `VAULT_ADDR` is properly set on machines you would like to use `mrmanager` on. Each function (`mrmanager {aws,rds}`) has decent help text that will tell you what the defaults are. 

## What about support?

This is a tool we're using internally, but it's not an officially supported item - i.e. open an issue, but please don't email our support department for help with this tool. Support on this tool is best-effort; we make no guarantees or warranties that this will work in your environment.

## Contributing
Before you start contributing to any project sponsored by F5, Inc. (F5) on GitHub, you will need to sign a Contributor License Agreement (CLA). This document can be provided to you once you submit a GitHub issue that you contemplate contributing code to, or after you issue a pull request.

If you are signing as an individual, we recommend that you talk to your employer (if applicable) before signing the CLA since some employment agreements may have restrictions on your contributions to other projects. Otherwise by submitting a CLA you represent that you are legally entitled to grant the licenses recited therein.

If your employer has rights to intellectual property that you create, such as your contributions, you represent that you have received permission to make contributions on behalf of that employer, that your employer has waived such rights for your contributions, or that your employer has executed a separate CLA with F5.

If you are signing on behalf of a company, you represent that you are legally entitled to grant the license recited therein. You represent further that each employee of the entity that submits contributions is authorized to submit such contributions on behalf of the entity pursuant to the CLA.