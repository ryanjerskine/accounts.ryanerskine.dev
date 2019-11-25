# accounts.ryanerskine.dev

An opinionated, production ready IdentityServer implementation.

## Getting Started

Clone the repository

```
git clone https://github.com/ryanjerskine/accounts.ryanerskine.dev.git
```

Update the .env file to point to an appropriate SQL server and adjust any other settings as needed.

### Prerequisites

You will need the [.NET Core 3 SDK](https://dotnet.microsoft.com/download/dotnet-core/3.0) installed.
This implementation was designed with [Docker](https://www.docker.com/products/docker-desktop) in mind, but can be configured to run without docker as well.
You will also need SQL server set up. By default, it will use (LocalDb)\MSSQLLocalDB but can be configured via the .env file.

### Local Database Setup

Setting up a local database is relatively easy
* Launch SSMS and connect to (localdb)\ProjectsV13 using Windows Authentication
* Create a database named IdentityServer
* Open the DbUp project and launch the project

### Environment Setup

Certain environment variables are required for the project to run correctly. The easiest way to get started is to rename sample.env to .env.
The project will handle loading any variables in that file into environment variables that will be read during startup.

## Running the tests

There are currently no tests. Feel free to submit a PR to start adding them.

### And coding style tests

TODO: Add stylecop or similar

## Deployment

### Terraform and Azure

The projects assumes (due to my limited time and knowledge) that you will be deploying to Azure using Terraform. Since the core project
is only relying on MS SQL and Docker, it should be rather simple to deploy to other environments by modifying the terraform. PRs are
always welcome.

### Terraform Configuration

Visit https://shell.azure.com/. If you have multiple subscriptions, you can set your subscription id using:

```
az account list --query "[].{name:name, subscriptionId:id, tenantId:tenantId}"
az account set --subscription="your id goes here"
```

Once you have your subscription id, you should then set up a service principal by running:

```
az ad sp create-for-rbac --role="Contributor" --scopes="/subscriptions/your id goes here"
```

which will return your appId, password, sp_name, and tenant. Make note of these.

## Built With

* [.NET Core](https://docs.microsoft.com/en-us/dotnet/core/)
* [IdentityServer4](https://github.com/IdentityServer/IdentityServer4)
* [Docker](https://www.docker.com/)

## Contributing

Please read [CONTRIBUTING.md](https://github.com/ryanjerskine/accounts.ryanerskine.dev/blob/master/CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## Versioning

We use [SemVer](http://semver.org/) for versioning.

## Authors

* **Ryan Erskine** - *Initial work*

See also the list of [contributors](https://github.com/ryanjerskine/accounts.ryanerskine.dev/graphs/contributors) for this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* [IdentityServer4](https://github.com/IdentityServer/IdentityServer4) and all of the contributors
