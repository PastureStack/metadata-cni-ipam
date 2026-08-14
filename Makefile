.RECIPEPREFIX := >

all: build

build:
>./scripts/build

test:
>./scripts/test

package:
>./scripts/package

validate:
>./scripts/validate

.PHONY: all build test package validate
