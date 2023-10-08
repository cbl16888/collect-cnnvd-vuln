package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cheggaaa/pb"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/y4ney/collect-cnnvd-vuln/internal/cnnvd"
	"github.com/y4ney/collect-cnnvd-vuln/internal/config"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "打印 collect-cnnvd-vuln 的版本",
	Long:  `所有的软件导游版本，collect-cnnvd-vuln也不例外`,
	RunE:  runPrintVersion,
}

func runPrintVersion(_ *cobra.Command, _ []string) error {
	fmt.Fprintf(out, "%s version %s\n", config.AppName, config.AppVersion)
	fmt.Fprintf(out, "build date: %s\n", config.BuildTime)
	fmt.Fprintf(out, "commit: %s\n\n", config.LastCommitHash)
	fmt.Fprintln(out, "https://github.com/y4ney/collect-cnnvd-vuln")

	var codes []string = []string{"CNNVD-202207-2089", "CNNVD-202212-3335", "CNNVD-202304-662"}
	currentTime := time.Now()
	var fileName = currentTime.Format("2006-01-02 15-04-05") + ".csv"
	file, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		log.Fatal().Msgf("file open error:%v", err)
	}
	var index = 0
	for _, code := range codes {
		index += 1
		reqAllVuln(code, file, index)
	}
	defer file.Close()
	return nil
}

func reqAllVuln(code string, file *os.File, index int) {
	c := cnnvd.ReqVulList{
		PageIndex:   PageIndex,
		PageSize:    PageSize,
		Keyword:     code,
		HazardLevel: level[HazardLevel],
		Vendor:      Vendor,
		Product:     Product,
		VulName:     VulName,
	}
	vulns, err := c.Fetch(Retry)
	if err != nil {
		log.Fatal().Interface("request", c).Int("retry", Retry).
			Msgf("failed to search vulns:%v", err)
	}
	log.Info().Interface("request", c).Int("retry", Retry).
		Msg("success to request... ...")
	if len(vulns) == 0 {
		log.Info().Interface("request", c).Int("retry", Retry).
			Msg("there is no record")
		return
	}
	bar := pb.StartNew(len(vulns))
	var customData [][]string

	for _, vuln := range vulns {
		detailC := cnnvd.ReqVulDetail{Id: vuln.Id, VulType: vuln.VulType, CnnvdCode: vuln.CnnvdCode}
		detail, err := detailC.Fetch(Retry)
		log.Debug().Interface("request", detailC).Int("retry", Retry).
			Msg("success to request... ...")
		if err != nil {
			log.Fatal().Interface("request", detailC).Int("retry", Retry).
				Msgf("failed to search vuln detail:%v", err)
		}
		customData = append(customData, []string{detail.VulName, detail.CnnvdCode, detail.CveCode,
			detail.VulDesc, "已修复：" + detail.Patch, severity[detail.HazardLevel], "", detail.VulType})
		// fmt.Println(detail)
		var score = 0.0
		if detail.HazardLevel == 1 {
			score = 9.1
		} else if detail.HazardLevel == 2 {
			score = 7.5
		} else if detail.HazardLevel == 3 {
			score = 5.3
		} else if detail.HazardLevel == 4 {
			score = 3.2
		}
		var desc = strings.ReplaceAll(detail.VulDesc, "\r\n", "")
		data := fmt.Sprint(index) + ". " + detail.CnnvdCode + ",,,\n" +
			"漏洞名称," + detail.VulName + ",,\n" +
			"CNNVD编号," + detail.CnnvdCode + ",危害等级," + severity[detail.HazardLevel] + "\n" +
			"CVE编号," + detail.CveCode + ",漏洞评分," + fmt.Sprint(score) + "\n" +
			"厂商," + detail.AffectedVendor + ",漏洞类型," + detail.VulType + "\n" +
			"漏洞简介," + desc + ",,\n" +
			"修复情况," + "已修复：" + detail.Patch + ",,\n"
		count, err := file.WriteString(data)
		if err != nil || count == 0 {
			log.Fatal().Msgf("file wirte error:%v", err)
		}
		bar.Increment()
	}
	bar.Finish()
	var indexJ = 0
	for _, row := range customData {
		fmt.Println("---------------" + fmt.Sprint(indexJ) + "---------------")
		for _, cell := range row {
			fmt.Println(cell)
		}
		indexJ += 1
	}
}
