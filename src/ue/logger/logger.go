package logger

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"os"
	"runtime"
	"strings"
)

var log *logrus.Logger
var AppLog *logrus.Entry
var InitLog *logrus.Entry
var ContextLog *logrus.Entry
var RunLog *logrus.Entry
var RegistrationLog *logrus.Entry
var DeregistrationLog *logrus.Entry
var HandlerLog *logrus.Entry
var IKELog *logrus.Entry

func init() {
	log = logrus.New()
	log.SetReportCaller(true)

	log.Formatter = &logrus.TextFormatter{
		ForceColors:               true,
		DisableColors:             false,
		EnvironmentOverrideColors: false,
		DisableTimestamp:          false,
		FullTimestamp:             true,
		TimestampFormat:           "",
		DisableSorting:            false,
		SortingFunc:               nil,
		DisableLevelTruncation:    false,
		QuoteEmptyFields:          false,
		FieldMap:                  nil,
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			orgFilename, _ := os.Getwd()
			repopath := orgFilename
			repopath = strings.Replace(repopath, "/bin", "", 1)
			filename := strings.Replace(f.File, repopath, "", -1)
			return fmt.Sprintf("%s()", f.Function), fmt.Sprintf("%s:%d", filename, f.Line)
		},
	}

	AppLog = log.WithFields(logrus.Fields{"UE": "app"})
	InitLog = log.WithFields(logrus.Fields{"UE": "init"})
	ContextLog = log.WithFields(logrus.Fields{"UE": "Context"})
	RunLog = log.WithFields(logrus.Fields{"UE": "Run"})
	RegistrationLog = log.WithFields(logrus.Fields{"UE": "Registration"})
	DeregistrationLog = log.WithFields(logrus.Fields{"UE": "Deregistration"})
	HandlerLog = log.WithFields(logrus.Fields{"UE": "Handler"})
	IKELog = log.WithFields(logrus.Fields{"UE": "IKE"})
	/*
		f, err := os.OpenFile("logrusOutput.log", os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)
		if err != nil {
			fmt.Printf("error opening file: %v", err)
		}

		// don't forget to close it
		//defer f.Close()

		// assign it to the standard logger
		log.SetOutput(f)
	*/
}

func SetLogLevel(level logrus.Level) {
	log.SetLevel(level)
}

func SetReportCaller(bool bool) {
	log.SetReportCaller(bool)
}
