# github repo watcher

This tool checks github repositories for:
* latest releases
* latest commits on a specific branch (**default** = `master`)
* latest tags

Results are stored into a database for later reference. I.e.

It can be run regularly (cronjob, AWS Lambda, ...) to provide up-to-date results.

## python and dependencies

* `python3` is used.
* Have a look at `requirementsx.txt`.

## use

The configuration (adding/removing repositories) still needs to be done right within `git_watcher.py`.

Install dependencies
```
virtualenv -q -p /usr/bin/python3
. venv/bin/activate
```

Initialise database when working locally
```
# start postgres
docker run -d --name db -p 5432:5432 postgres:alpine
# create test table
docker run --rm -it --net=host postgres:alpine sh  # or docker exec -it db sh
# within the container
$ psql -h localhost -Upostgres
# within postgres
>$ create database test;
>$\q
$exit
```

Run the github watcher
```
python git_watcher.py
```

## database

The configuration (`DATABASE_URL`) still needs to be done right within `git_watcher.py`.
When using AWS lambda, `DATABASE_URL` is read as an encrypted AWS Lambda environment variable - Please also see **zappa for AWS Lambda** and **secrets**.

Right now it is possible to use `sqlite` and `postgres`, although that can be easily enhanced.

## webhooks

This is not completely implemented/integrated but it is thought to provide events, that can be triggered, if new tags e.g. were found.

`check github_repo -> get latest tag -> compare to values in database -> tag was not seen before (new tag) -> `

## zappa for AWS Lambda

To keep the database up-to-date, I let the script run as a function in AWS Lambda.
It is configured to every hour.

```
# initialise zappa
zappa init
# customize the settings to your needs
vim zappa_settings.json
# deploy, environemnt is called "dev" in this case
aws-vault-css-sideprojects -- zappa deploy dev
or
aws-vault-css-sideprojects -- zappa update dev
```

### secrets

The database url `DATABASE_URL` is read as an AWS Lambda environment variable which is encrypted with a custom AWS KMS key.
I specifically allow the AWS IAM Role created by zappa (`github-repo-wat-dev-ZappaLambdaExecutionRole`) to decrypt values encrypted with this custom AWS KMS key.
This can be set in the AWS KMS settings of the key.

For this to work `zappa_settings.json` needs to contain the AWS KMS key ARN: `arn:aws:kms:eu-west-1:733052150360:key/aa9dc195-e04e-41ca-a727-00a8a78b926d`.

Code to read/decrypt the values is provided by AWS Lambda (Fucntion Configuration, below the Designer).


## logging

When used in combination with AWS lambda, AWS CloudWatch is used automatically.

The program itself prints log `INFO` messages.

## tests

There a re no tests, yet. There should be tests :)
