package main

import (
	"time"

	getopt "github.com/pborman/getopt/v2"
)

type stringArrayFlag []string

type durationFlag time.Duration

func (stringArray *stringArrayFlag) Set(value string, _ getopt.Option) error {
	*stringArray = append(*stringArray, value)
	return nil
}

func (stringArray *stringArrayFlag) String() string {
	return ""
}

func (duration *durationFlag) Set(value string, _ getopt.Option) error {
	parsedDuration, err := time.ParseDuration(value)
	*duration = durationFlag(parsedDuration)
	return err
}

func (duration *durationFlag) String() string {
	return ""
}
