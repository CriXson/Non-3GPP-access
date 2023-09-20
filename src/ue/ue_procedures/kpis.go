package ue_procedures

import (
	"encoding/csv"
	"log"
	"os"
	"strconv"
	"time"
)

type Record struct {
	paketCounter           int
	rtts                   []int64
	paketRetransmission    int
	errors                 int
	authenticationDuration string
	rttIndex               int
	startTime              time.Time
	filename               string
	errorReason            string
}

func WriteHeader(filename string) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		f, err := os.OpenFile(filename+".csv", os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		w := csv.NewWriter(f)
		data := []string{"PaketCounter", "RTT Average", "Authentication Duration", "Paket Retransmission Counter", "Error Counter", "Error String"}
		err = w.Write(data)
		if err != nil {
			log.Fatalf("Error %d", err)
		}
		w.Flush()
		f.Close()
		pingLog.Info("Wrote Header")
	}
}
func (rec *Record) WriteToCSV(filename string) {
	f, err := os.OpenFile(filename+".csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	w := csv.NewWriter(f)

	var sum int64
	for _, x := range rec.rtts {
		sum += x
	}
	avg := sum / int64(len(rec.rtts))
	duration := rec.authenticationDuration
	log.Printf("duration  %d", duration)
	data := []string{strconv.Itoa(rec.paketCounter), strconv.FormatInt(avg, 10), duration,
		strconv.Itoa(rec.paketRetransmission), strconv.Itoa(rec.errors), rec.errorReason}

	w.Write(data)
	if err != nil {
		log.Fatalf("Error %d", err)
	}
	w.Flush()
	err = w.Error()
	log.Printf("csv writer error %d", err)
	f.Close()
}

func (rec *Record) addToRtt(duration time.Duration) {
	if rec.rtts[0] == 0 {
		rec.rtts[0] = duration.Milliseconds()
	} else {
		rec.rtts = append(rec.rtts, duration.Milliseconds())
	}
}

func authStarted(filename string) {
	f, err := os.OpenFile(filename+".csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	w := csv.NewWriter(f)

	data := []string{"auth started"}

	w.Write(data)
	if err != nil {
		log.Fatalf("Error %d", err)
	}
	w.Flush()
	err = w.Error()
	log.Printf("csv writer error %d", err)
	f.Close()
}
