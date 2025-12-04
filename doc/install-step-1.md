# create an OpenAI admin API key
First you will create a **OpenAI admin key**. This key will be used to make API calls to the audit log endpoint.

In the [OpenAI admin console](https://platform.openai.com/settings/organization/admin-keys) create a new Admin key of type `Read only`. Note the key somewhere safe, since you will not be able to access it later on.

Do not use a regular user API key as those do not have access to the audit log.

Also obtain your OpenAI Organisation Id in the [General menu option](https://platform.openai.com/settings/organization/general).
