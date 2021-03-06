# igia server-side libraries

This project contains igia server side libraries.

- igia-lib-parent
- igia-hipaa-audit-autoconfig

## igia-lib-parent

igia-lib-parent contains Maven dependency management for igia libraries.

The primary use case for igia-lib-parent is to simplify Maven dependency management for a igia library project.

igia-lib-parent will be published to the maven central repository and be freely available.

### Background

igia-lib-parent is created to facilitate using Maven Dependency Management when creating a jar library that is intended to be used in a JHipster generated gateway or microservice. Please check [Maven Dependency Management document](https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html) if you are not familiar with the Maven dependency management.

igia-lib-parent is built on top of jhipster-dependencies, which is used for all JHipster generated project.

If you are creating a library (jar) to be included in a JHipster generated gateway or microservice project, you should use igia-lib-parent as the parent pom to make sure you are selecting the right versions of dependencies.

The dependency chain will be:

{your_lib_artifact} --> igia-lib-parent --> jhipster-dependencies

For example, for igia-hipaa-audit-autoconfig, the version dependency chain is:

igia-hipaa-audit-autoconfig 0.3.3 --> igia-lib-parent 0.3.3 --> jhipster-dependencies 2.0.25. Jhipster-dependencies 2.0.25 is used by JHipster generator 5.4.2, thus, igia-hipaa-audit-autoconfig can be included directly into a JHipster 5.4.2 generated gateway project.

The above chain will also make it is easy to upgrade your library to the newer version of jhipster-dependencies and thus used in a gateway or microservice generated by a newer version of JHipster. For example, for igia-hipaa-audit-autoconfig 0.3.3 can be used in a gateway project generated by JHipster 5.8.2 since the version dependency is:

igia-hipaa-audit-autoconfig 0.3.3 --> igia-lib-parent 0.3.3 --> jhipster-dependencies 2.1.0.

### How to use igia-lib-parent

The beginning of your pom.xml should be like:

```maven
    <parent>
        <groupId>io.igia</groupId>
        <artifactId>igia-lib-parent</artifactId>
        <version>0.3.3</version>
    </parent>

    <artifactId>{your_lib_artifactId}</artifactId>
    <packaging>jar</packaging>
    <name>{Your lib name}</name>
    <description>{Your lib description}</description>
    <version>0.3.3</version>
```

The next step is to identify the other libraries that your library will depend on. For example, if your project depends on `commons-io` and `spring-security-core` and another `{third_party_artifact}` (assuming it is part of jhipster-dependencies), you can just include the following code in the `pom.xml` file. Note there is no need to include the version for the libraries. If you are including a third party library that is not part of jhipster-dependencies, you also need to add the version of the third party library.

```maven
   <dependencies>
        <dependency>
            <groupId>commons-io</groupId>
            <artifactId>commons-io</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-core</artifactId>
        </dependency>
        <dependency>
            <groupId>{third_party_groupId}</groupId>
            <artifactId>{third_party_artifactId}</artifactId>
        </dependency>
    </dependencies>
```

Please use the igia-hipaa-audit-autoconfig `pom.xml` as an example.

## igia-hipaa-audit-autoconfig

igia-hipaa-audit-autoconfig is a Spring Boot auto-configuration library to add HIPAA auditing capability to JHipster generated Gateway project.

To include igia-hipaa-audit-autoconfig in a gateway project, simply add the following dependency to your gateway project:

```maven
        <!-- jhipster-needle-maven-add-dependency -->
        <dependency>
            <groupId>io.igia</groupId>
            <artifactId>igia-hipaa-audit-autoconfig</artifactId>
            <version>0.3.3</version>
        </dependency>
```

## License and Copyright
MPL 2.0 w/ HD  
See [LICENSE](LICENSE) file.  
See [HEALTHCARE DISCLAIMER](HD.md) file.  
© [Persistent Systems, Inc.](https://www.persistent.com)
