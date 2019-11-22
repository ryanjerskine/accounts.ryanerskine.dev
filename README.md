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

## Running the tests

There are currently no tests. Feel free to submit a PR to start adding them.

### And coding style tests

TODO: Add stylecop or similar

## Deployment

TODO: Add instructions for deployment to Azure.

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
