package com.killua.simulator.controller;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import com.killua.simulator.util.PkiSimulatorConfig;

@Controller
@RequestMapping(value = "/api/v1")
public class PkiSimulatorController {

	private static final Logger LOG = LoggerFactory.getLogger(PkiSimulatorController.class);
	
	@RequestMapping(value = "/certificate", method = RequestMethod.GET)
	public ResponseEntity<String> getPkiCertificate(@RequestParam("vin") String vin, @RequestParam("ecutype") String ecutype) {
		String certificate = "";
		try {
			if (null == vin || vin.isEmpty() || null == ecutype || ecutype.isEmpty()) {
				System.out.println("Vin and ecutype cannot be null or empty.");
				LOG.error("Vin and ecutype cannot be null or empty.");
				return new ResponseEntity<>(certificate, HttpStatus.BAD_REQUEST);
			}
			String fname = vin + "_" + ecutype + ".txt";
			certificate = findVinFile(fname);
			if (null == certificate || certificate.isEmpty()) {
				System.out.println("The certificate of vin[" + vin + "] & ecutype[" + ecutype + "] is empty.");
				LOG.error("The certificate of vin[{}] & ecutype[{}] is empty.", vin, ecutype);
				return new ResponseEntity<>(certificate, HttpStatus.NO_CONTENT);
			}
			System.out.println("Certificate info: " + certificate);
			LOG.info("Certificate info: {}", certificate);
			return new ResponseEntity<>(certificate, HttpStatus.OK);
		} catch (Exception e) {
			System.out.println("Exception happends while getPkiCertificate: " + e.getMessage());
			LOG.error("Exception happends while getPkiCertificate: {}", e);
			return new ResponseEntity<>(certificate, HttpStatus.BAD_REQUEST);
		}
	}
	
	private String findVinFile(String filename) throws Exception {
		String path = PkiSimulatorConfig.getString("certificate.path");
		String certificate = "";
		if (null == path || path.isEmpty())
			return "";
		File file = new File(path + System.getProperty("file.separator") + filename);
		if (!file.exists()) {
			System.out.println("Cannot find the file: " + file.toString());
			LOG.warn("Cannot find the file: {}", file.toString());
			return "";
		} else if (!file.isFile()) {
			System.out.println(file.toString() + "is not a file.");
			LOG.warn("[{}] is not a file.", file.toString());
			return "";
		} else {
			BufferedReader br = new BufferedReader(new FileReader(file));
			String read = "";
			while (null != (read = br.readLine()))
				certificate += read;
			br.close();
		}
		return certificate;
	}
}
