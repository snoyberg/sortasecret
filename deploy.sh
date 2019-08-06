#!/bin/sh

exec helm upgrade --install sortasecret-prod helm -f helm/values/prod.yaml
