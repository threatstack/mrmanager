>**Michael:** Well, I’ll tell you what. I’m going to give you a promotion. Welcome aboard, Mr. Manager.
>
>**George Michael:** Wow. I’m Mr. Manager!
>
>**Michael:** Well, manager; we just say manager.

_It's up to you -- you're the manager now!_

# mrmanager

`mrmanager` is a tool we use internally to get credentials and write them to the correct place. It's a UI wrapper around Vault. It was one of our first golang tools here at Threat Stack. `mrmanager` has opinions about the way you set up Vault and your infrastructure:

* You have Vault configured to give you AWS tokens - either at `aws/` (default) or `aws-envname/` (`-e` flag with `mrmanager aws`).
* You have Vault configured to give you database credentials using the `database/` endpoint, and you name all your roles `dbname-rolename` with `readonly` being a good default role. Additionally, your databases:
  * Are in AWS RDS, and the host your run from has the `rds:DescribeDBInstances` permission.
  * Use standard ports; 5432 for PostgreSQL and 3306 for MySQL
* You use the Duo MFA integration.

## How can I use it?
Setting up vault is outside the scope of this tool's documentation, but fortunately [Vault](https://www.vaultproject.io/docs/)'s documentation is decent.

You will likely need to make modifications to `mrmanager` to fit your environment. We chose to open-source this because having this template is a handy start to ease your fellow engineers and users into generating limited-time tokens for databases and AWS.

Ensure `VAULT_ADDR` is properly set on machines you would like to use `mrmanager` on. Each function (`mrmanager {aws,rds}`) has decent help text that will tell you what the defaults are. 

## What about support?

This is a tool we're using internally, but it's not an offically supported item - i.e. open an issue, but please don't email our support department for help with this tool. We're happy to take pull requests, but the main reason we're releasing this is that it might help other folks in the same pickle. Support on this tool is best-effort; we make no guarantees or warranties that this will work in your environment.

## Contributing
Contributions are welcome; this is one of our first golang projects and we understand it's messy :) 

Open a PR with your changes and we're happy to take a look!
