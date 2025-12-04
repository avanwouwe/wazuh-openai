# wazuh-openai
Wazuh wodle that integrates all OpenAI audit events (including logins, modification of API keys or spending limits).

![screenshot of OpenAI events in Wazuh](/doc/openai%20screenshot.png)

## Disadvantages / limitations:
* batch-driven instead of event-driven, resulting in a delay between the event and it's recovery
* the `@timestamp` of events is the moment of injection, not the moment of the event, which is stored in `data.timestamp`

## Installation:
* [create admin API key](/doc/install-step-1.md)
* [install wodle](/doc/install-step-2.md)

## Frequently Asked Questions

### What if I have several OpenAI tenants?
Just follow the installation procedure several times. So:
* create an admin API key in each tenant
* create separate directories
  * /var/ossec/wodles/openai-tenant-A/
  * /var/ossec/wodles/openai-tenant-B/
  * etc
* create the respective admin API keys, and place them in the `config.json` of their directories.
* in `ossec.conf` create separate `<wodle>`entries, where the `<command>`is changed:
```
  <wodle name="command">
    <disabled>no</disabled>
    <tag>openai</tag>
    <command>/var/ossec/wodles/openai-tenant-A/openai -o 8</command>
    <interval>10m</interval>
    <ignore_output>no</ignore_output>
    <run_on_start>yes</run_on_start>
    <timeout>0</timeout>
  </wodle>
```

All the events include a `data.openai.org_id` that identifies the OpenAI Organisation ID. If you want a specific label you can add a `<tag>name</tag>` to the `ossec.conf`.

## Attribution
This contribution was originally developed by [bzhkem](https://github.com/bzhkem) and uploaded with his permission.
