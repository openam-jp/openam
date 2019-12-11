# OpenAM (OpenAM Consortium Edition)

OpenAM is an "all-in-one" access management solution that provides Authentication,
Authorization, Entitlement and Federation features.

## Documentation

This project provides documentation on [GitHub wiki pages][github_wiki].

## Getting the OpenAM Application

You can obtain the OpenAM WAR file from [GitHub releases pages][github_releases].

## Build from Source Code

### Prerequisites

Software               | Required Version
---------------------- | ----------------
OpenJDK                | 1.8 and above
Maven                  | 3.1.0 and above
Git                    | 1.7.6 and above

### Build

The OpenAM build process and dependencies are managed by Maven.

At this time, OpenAM and related products are not registered in the Maven repository, so it is necessary to build all projects until the Maven local repository is ready.

Please, check out the following projects and run `mvn clean install` in order.

In addition, don't forget to execute the commands as a non-root user.

* [forgerock-parent](https://github.com/openam-jp/forgerock-parent)
* [forgerock-bom](https://github.com/openam-jp/forgerock-bom)
* [forgerock-build-tools](https://github.com/openam-jp/forgerock-build-tools)
* [forgerock-i18n-framework](https://github.com/openam-jp/forgerock-i18n-framework)
* [forgerock-guice](https://github.com/openam-jp/forgerock-guice)
* [forgerock-ui](https://github.com/openam-jp/forgerock-ui)
* [forgerock-guava](https://github.com/openam-jp/forgerock-guava)
* [forgerock-commons](https://github.com/openam-jp/forgerock-commons)
* [forgerock-persistit](https://github.com/openam-jp/forgerock-persistit)
* [forgerock-bloomfilter](https://github.com/openam-jp/forgerock-bloomfilter)
* [opendj-sdk](https://github.com/openam-jp/opendj-sdk)
* [opendj](https://github.com/openam-jp/opendj)
* [openam](https://github.com/openam-jp/openam)

Finally, Maven builds the binary in `openam/openam-server/target`. The file name format is `OpenAM-<version>.war`.

## Contributing

This project welcomes your contributions.

If you find a bug or have an improvement idea, please open an [issue][github_issues] as the first step.
However, if it contains security problems, please [email us][mail_openam_dev] without opening an issue.

## License

This project is licensed under the Common Development and Distribution License (CDDL).

## Acknowledgments

* Sun Microsystems.
* ForgeRock.
* The good things in life.

## Languages

* [日本語](README_ja.md)

[mail_openam_dev]: mailto:openam-dev@OpenAM.jp
[github_issues]: https://github.com/openam-jp/openam/issues
[github_wiki]: https://github.com/openam-jp/openam/wiki
[github_releases]: https://github.com/openam-jp/openam/releases

