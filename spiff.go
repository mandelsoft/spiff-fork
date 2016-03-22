package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"

	"github.com/codegangsta/cli"

	"github.com/cloudfoundry-incubator/candiedyaml"
	"github.com/cloudfoundry-incubator/spiff/compare"
	"github.com/cloudfoundry-incubator/spiff/debug"
	"github.com/cloudfoundry-incubator/spiff/dynaml"
	"github.com/cloudfoundry-incubator/spiff/flow"
	"github.com/cloudfoundry-incubator/spiff/password"
	"github.com/cloudfoundry-incubator/spiff/yaml"
)

func main() {
	app := cli.NewApp()
	app.Name = "spiff"
	app.Usage = "BOSH deployment manifest toolkit"
	app.Version = "1.0.8-dev.4"

	app.Commands = []cli.Command{
		{
			Name:      "merge",
			ShortName: "m",
			Usage:     "merge stub files into a manifest template",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "debug",
					Usage: "print state info",
				},
				cli.BoolFlag{
					Name:  "partial",
					Usage: "allow partial evaluation only",
				},
			},
			Action: func(c *cli.Context) {
				if len(c.Args()) < 1 {
					cli.ShowCommandHelp(c, "merge")
					os.Exit(1)
				}
				debug.DebugFlag = c.Bool("debug")
				merge(c.Args()[0], c.Bool("partial"), c.Args()[1:])
			},
		},
		{
			Name:      "diff",
			ShortName: "d",
			Usage:     "structurally compare two YAML files",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "separator",
					Usage: "separator to print between diffs",
				},
			},
			Action: func(c *cli.Context) {
				if len(c.Args()) > 2 || len(c.Args()) < 1 {
					cli.ShowCommandHelp(c, "diff")
					os.Exit(1)
				}

				diff(c.Args()[0], c.Args()[1], c.String("separator"))
			},
		},

		{
			Name:      "passwords",
			ShortName: "p",
			Usage:     "update password file/query password",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "passphrase",
					Usage: "passphrase used to de/encode passwords (default $SPIFF_PASSPHRASE)",
				},
			},
			Action: func(c *cli.Context) {
				if len(c.Args()) > 2 {
					cli.ShowCommandHelp(c, "passwords")
					os.Exit(1)
				}

				passwords(c.Args(), c.String("passphrase"))
			},
		},

		{
			Name:      "encrypt",
			ShortName: "e",
			Usage:     "encrypt string",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "passphrase",
					Usage: "passphrase used to de/encode passwords (default $SPIFF_PASSPHRASE)",
				},
			},
			Action: func(c *cli.Context) {
				if len(c.Args()) > 2 || len(c.Args()) < 1 {
					cli.ShowCommandHelp(c, "encrypt")
					os.Exit(1)
				}

				encrypt(c.Args(), c.String("passphrase"))
			},
		},
	}

	app.Run(os.Args)
}

func merge(templateFilePath string, partial bool, stubFilePaths []string) {
	var templateFile []byte
	var err error
	var stdin = false

	if templateFilePath == "-" {
		templateFile, err = ioutil.ReadAll(os.Stdin)
		stdin = true
	} else {
		templateFile, err = ioutil.ReadFile(templateFilePath)
	}

	if err != nil {
		log.Fatalln(fmt.Sprintf("error reading template [%s]:", path.Clean(templateFilePath)), err)
	}

	templateYAML, err := yaml.Parse(templateFilePath, templateFile)
	if err != nil {
		log.Fatalln(fmt.Sprintf("error parsing template [%s]:", path.Clean(templateFilePath)), err)
	}

	stubs := []yaml.Node{}

	for _, stubFilePath := range stubFilePaths {
		var stubFile []byte
		var err error
		if stubFilePath == "-" {
			if stdin {
				log.Fatalln(fmt.Sprintf("stdin cannot be used twice"))
			}
			stubFile, err = ioutil.ReadAll(os.Stdin)
			stdin = true
		} else {
			stubFile, err = ioutil.ReadFile(stubFilePath)
		}
		if err != nil {
			log.Fatalln(fmt.Sprintf("error reading stub [%s]:", path.Clean(stubFilePath)), err)
		}

		stubYAML, err := yaml.Parse(stubFilePath, stubFile)
		if err != nil {
			log.Fatalln(fmt.Sprintf("error parsing stub [%s]:", path.Clean(stubFilePath)), err)
		}

		stubs = append(stubs, stubYAML)
	}

	flowed, err := flow.Cascade(templateYAML, partial, stubs...)
	if !partial && err != nil {
		legend := "\nerror classification:\n" +
			" *: error in local dynaml expression\n" +
			" @: dependent of or involved in a cycle\n" +
			" -: depending on a node with an error"
		log.Fatalln("error generating manifest:", err, legend)
	}
	if err != nil {
		flowed = dynaml.ResetUnresolvedNodes(flowed)
	}
	yaml, err := candiedyaml.Marshal(flowed)
	if err != nil {
		log.Fatalln("error marshalling manifest:", err)
	}

	fmt.Println(string(yaml))
}

func diff(aFilePath, bFilePath string, separator string) {
	aFile, err := ioutil.ReadFile(aFilePath)
	if err != nil {
		log.Fatalln(fmt.Sprintf("error reading a [%s]:", path.Clean(aFilePath)), err)
	}

	aYAML, err := yaml.Parse(aFilePath, aFile)
	if err != nil {
		log.Fatalln(fmt.Sprintf("error parsing a [%s]:", path.Clean(aFilePath)), err)
	}

	bFile, err := ioutil.ReadFile(bFilePath)
	if err != nil {
		log.Fatalln(fmt.Sprintf("error reading b [%s]:", path.Clean(bFilePath)), err)
	}

	bYAML, err := yaml.Parse(bFilePath, bFile)
	if err != nil {
		log.Fatalln(fmt.Sprintf("error parsing b [%s]:", path.Clean(bFilePath)), err)
	}

	diffs := compare.Compare(aYAML, bYAML)

	if len(diffs) == 0 {
		fmt.Println("no differences!")
		return
	}

	for _, diff := range diffs {
		fmt.Println("Difference in", strings.Join(diff.Path, "."))

		if diff.A != nil {
			ayaml, err := candiedyaml.Marshal(diff.A)
			if err != nil {
				panic(err)
			}

			fmt.Printf("  %s has:\n    \x1b[31m%s\x1b[0m\n", aFilePath, strings.Replace(string(ayaml), "\n", "\n    ", -1))
		}

		if diff.B != nil {
			byaml, err := candiedyaml.Marshal(diff.B)
			if err != nil {
				panic(err)
			}

			fmt.Printf("  %s has:\n    \x1b[32m%s\x1b[0m\n", bFilePath, strings.Replace(string(byaml), "\n", "\n    ", -1))
		}

		fmt.Printf(separator)
	}
}

func passwords(args []string, passphrase string) {
	if passphrase == "" {
		passphrase = os.Getenv("SPIFF_PASSPHRASE")
	}
	if passphrase == "" {
		log.Fatalln(fmt.Sprintf("passphrase required to update password file %s", path.Clean(args[0])))
	}
	var err error
	var p string
	if len(args) == 2 {
		p, err = password.GetPassword(args[1], args[0], passphrase)
		fmt.Printf("%s: %s\n", args[1], p)
	} else {
		_, err = password.GetPasswordFile(args[0], passphrase)
	}
	if err != nil {
		log.Fatalln(fmt.Sprintf("error during update of password file %s: ", path.Clean(args[0])), err)
	}
}

func encrypt(args []string, passphrase string) {
	if passphrase == "" {
		passphrase = os.Getenv("SPIFF_PASSPHRASE")
	}
	if passphrase == "" {
		log.Fatalln(fmt.Sprintf("passphrase required for encrypting '%s'", path.Clean(args[0])))
	}
	var err error
	enc := password.TRIPPLEDES
	if len(args) == 2 {
		enc = args[1]
	}
	e, ok := password.GetEncoding(enc)
	if !ok {
		log.Fatalln(fmt.Sprintf("invalid encoding '%s'", args[1]))
	}

	r, err := e.Encode(args[0], passphrase)
	if err != nil {
		log.Fatalln(fmt.Sprintf("error during encrypting '%s': ", args[0]), err)
	}
	fmt.Printf("%s\n", r)
}
