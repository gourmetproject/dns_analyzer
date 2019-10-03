package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/gourmetproject/dnsanalyzer/dnsresult"
	"github.com/gourmetproject/gourmet"
)

type dnsAnalyzer struct{}

func NewAnalyzer() gourmet.Analyzer {
	return &dnsAnalyzer{}
}

func (ha *dnsAnalyzer) Filter(c *gourmet.Connection) bool {
	if c.SourcePort == 53 || c.DestinationPort == 53 {
		return true
	}
	return false
}

func (ha *dnsAnalyzer) Analyze(c *gourmet.Connection) (gourmet.Result, error) {
	d := &dnsresult.DNS{}
	var dns layers.DNS
	var decoded []gopacket.LayerType
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeDNS, &dns)
	if err := parser.DecodeLayers(c.Payload.Bytes(), &decoded); err != nil {
		return nil, err
	}
	for _, layerType := range decoded {
		switch layerType {
		case layers.LayerTypeDNS:
			d = newDnsResult(dns)
		}
	}
	return d, nil
}

func newDnsResult(parsedDNS layers.DNS) (d *dnsresult.DNS) {
	d = &dnsresult.DNS{}
	d.ID = parsedDNS.ID
	d.QR = parsedDNS.QR
	d.OpCode = parsedDNS.OpCode.String()
	d.AA = parsedDNS.AA
	d.TC = parsedDNS.TC
	d.ResponseCode = parsedDNS.ResponseCode.String()
	d.Questions = newDNSQuestions(parsedDNS)
	d.Answers = newDNSRecords(parsedDNS.Answers)
	d.Authorities = newDNSRecords(parsedDNS.Authorities)
	d.Additionals = newDNSRecords(parsedDNS.Additionals)
	return d
}

func newDNSQuestions(parsedDNS layers.DNS) (dnsQuestions []dnsresult.Question) {
	for _, question := range parsedDNS.Questions {
		dnsQuestions = append(dnsQuestions, newDnsQuestion(question))
	}
	return dnsQuestions
}

func newDnsQuestion(question layers.DNSQuestion) (dnsQuestion dnsresult.Question) {
	dnsQuestion.Name = string(question.Name)
	dnsQuestion.Class = question.Class.String()
	dnsQuestion.Type = question.Type.String()
	return dnsQuestion
}

func newDNSRecords(records []layers.DNSResourceRecord) (dnsRecords []dnsresult.Record) {
	for _, record := range records {
		dnsRecords = append(dnsRecords, newDnsRecord(record))
	}
	return dnsRecords
}

func newDnsRecord(record layers.DNSResourceRecord) (dnsRecord dnsresult.Record) {
	dnsRecord.Name = string(record.Name)
	dnsRecord.Type = record.Type.String()
	dnsRecord.Class = record.Class.String()
	dnsRecord.Data = string(record.Data)
	if record.IP != nil {
		dnsRecord.IP = record.IP.String()
	}
	dnsRecord.NS = string(record.NS)
	dnsRecord.CNAME = string(record.CNAME)
	dnsRecord.PTR = string(record.PTR)
	dnsRecord.TXT = convertDNSTXTToStrings(record.TXTs)
	dnsRecord.SOA = newDnsSOA(record.SOA)
	return dnsRecord
}

func convertDNSTXTToStrings(txtBytes [][]byte) (txtStrings[]string) {
	for _, txt := range txtBytes {
		txtStrings = append(txtStrings, string(txt))
	}
	return txtStrings
}

func newDnsSOA(soa layers.DNSSOA) (dnsSOA dnsresult.SOA) {
	dnsSOA.MName = string(soa.MName)
	dnsSOA.RName = string(soa.RName)
	dnsSOA.Expire = soa.Expire
	dnsSOA.Refresh = soa.Refresh
	dnsSOA.Serial = soa.Serial
	dnsSOA.Retry = soa.Retry
	// new RFC renames MINIMUM to TTL, so we will too
	dnsSOA.TTL = soa.Minimum
	return dnsSOA
}

