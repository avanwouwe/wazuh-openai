> [!NOTE]  
> this wodle works on any Wazuh installation but this how-to assumes a [Wazuh docker deployment](https://github.com/wazuh/wazuh-docker) and may require (slight) adaptation for other deployment methods

# install wodle
Clone this repo in the directory where the Wazuh docker repo is cloned
```
> ls
wazuh-docker
> git clone https://github.com/avanwouwe/wazuh-openai.git
> ls
wazuh-docker/
wazuh-openai/
```

In the `docker-compose.yml` mount the `/wodle` directory of this repo so that it is available on the Wazuh master.
```
    volumes:
      - ../../wazuh-openai/wodle:/var/ossec/wodles/openai
```

Now you can rebuild the image and recreate the containers to ensure that the volume is mounted:
```
cd  ~/wazuh-docker/multi-node/
docker compose down
docker compose up -d --build
```

And then create a shell session on the master node:
```
cd  ~/wazuh-docker/multi-node/
docker compose exec -ti wazuh.master bash
cd /var/ossec/wodles/openai/
```

Configure your OpenAI Organisation Id and API key:
```
cat > config.json << EOF
{
  "apiKey": "sk-admin-xxxxxxxxxx",
  "orgId": "org-xxxxxx"
}
EOF
```

You can test that the wodle works by running it and checking that it outputs log events in JSON format. The `--unread` parameter ensures that the historical messages will be left unread for the next run. 
```
./openai --unread
```

You can then close the shell session.

# add rules
Events only generate alerts if they are matched by a rule. Go to the rules configuration and create a new rules file `0650-openai_rules.xml` and fill it with the contents of [/rules/0650-openai_rules.xml](/rules/0650-openai_rules.xml).

# change ossec.conf
Add this wodle configuration to `/var/ossec/etc/ossec.conf` to ensure that the wodle is called periodically by Wazuh. In the Wazuh-provided Docker installion this file is modified in `~/wazuh-docker/multi-node/config/wazuh_cluster`.
```
  <wodle name="command">
    <disabled>no</disabled>
    <tag>openai</tag>
    <command>/var/ossec/wodles/openai/openai -o 8</command>
    <interval>10m</interval>
    <ignore_output>no</ignore_output>
    <run_on_start>yes</run_on_start>
    <timeout>0</timeout>
  </wodle>
```

The wodle keeps track of the most recent event that has been extracted, and will start extracting from that time point on at the next extraction. The `-o` parameter configures the offset, or the maximum number of hours to go back in time. If the offset goes back too far in history, the extraction will return a lot of data and may time out the first time you run it. And if the offset is too short it will result in missed events, should the wodle stop running for longth than that period.

Restart the server for the changes to take effect, for example using the `Restart cluster` button in the `Server Management` > `Status` menu.

You should start seeing new events show up in the Threat hunting module. You can filter for `command: command_openai` to make it easier to see.

![screenshot of OpenAI events in Wazuh](/doc/openai%20screenshot.png)
