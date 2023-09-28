# Ai Study Tutor


## Quick Start
### 1. Spin up local dev env
```bash
> cd local-dev
> docker-compose up -d
```
### 2. Migrate schema
```bash
> ./gradlew :model:flywayMigrate
```

### 3. Build
```bash
> ./graldew build
```


## Code Style

We use [palantir-java-format](https://github.com/palantir/palantir-java-format) to format the code.
It's a slight variation on top of [google-java-format](https://github.com/google/google-java-format).
Install the palantir-java-format plugin in Intellij to auto format your code 
while developing. 
We also use the palantir-java-format gradle plugin 
to auto format the code before submit your PR. 

### install the palantir-java-format plugin in Intellij

A
[palantir-java-format IntelliJ plugin](https://plugins.jetbrains.com/plugin/13180)
is available from the plugin repository. To install it, go to your IDE's
settings and select the `Plugins` category. Click the `Marketplace` tab, search
for the `palantir-java-format` plugin, and click the `Install` button.

The plugin will be disabled by default on new projects, but as mentioned [above](#compalantirjava-format-gradle-plugin),
if using the `com.palantir.java-format` gradle plugin, it will be recommended
in IntelliJ, and automatically configured.

To manually enable it in the current project, go
to `File→Settings...→palantir-java-format Settings` (or `IntelliJ
IDEA→Preferences...→Other Settings→palantir-java-format Settings` on macOS) and
check the `Enable palantir-java-format` checkbox.

To enable it by default in new projects, use `File→Other Settings→Default
Settings...`.

When enabled, it will replace the normal `Reformat Code` action, which can be
triggered from the `Code` menu or with the Ctrl-Alt-L (by default) keyboard
shortcut.

## Immutables
We use [Immutables](https://github.com/immutables/immutables) annotation processors to 
generate simple, safe and consistent value objects.

Make sure to build the project before developing. 