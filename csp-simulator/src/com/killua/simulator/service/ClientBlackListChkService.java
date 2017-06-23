package com.killua.simulator.service;

import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.LineIterator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ClientBlackListChkService {

	private static final Logger LOG = LoggerFactory.getLogger(ClientBlackListChkService.class);
	
	private static final String BLACK_LIST_CONF = "blacklist.conf";
	
	private volatile long lastModified = 0L;
	
	private volatile Set<String> clientBlackList = null;
	
	public ClientBlackListChkService() {
		File file = getFile();
		this.loadConfg(file);
		this.lastModified = file.lastModified();
	}
	
	public void scanConfg() {
		File file = getFile();
		if (file.lastModified() > this.lastModified) {
			this.loadConfg(file);
			this.lastModified = file.lastModified();
		}
	}
	
	private File getFile() {
		URI uri;
		String filename = "";
		try {
			uri = ClientBlackListChkService.class.getClassLoader().getResource(BLACK_LIST_CONF).toURI();
			if(null == uri) {
				LOG.error("unable to find resource: {}", BLACK_LIST_CONF);
				throw new RuntimeException("unable to find resource: " + BLACK_LIST_CONF + ".");
			}
			filename = uri.getPath().replace('/', File.separatorChar);
			LOG.info("BlackList File: {}", filename);
		} catch (URISyntaxException e) {
			e.printStackTrace();
		}
		return new File(filename);
	}
	
	private void loadConfg(File file) {
		Set<String> tmpClientSet = new HashSet<>();
		LineIterator lit = null;
		try {
			lit = FileUtils.lineIterator(file);
			while (lit.hasNext()) {
				String line = lit.nextLine().trim();
				if (line.contains(",")) {
					String[] clientArray = line.split(",");
					for (int i = 0; i < clientArray.length; i++) {
						tmpClientSet.add(clientArray[i]);
					}
				} else {
					tmpClientSet.add(line);
				}
			}
		} catch (Exception e) {
			System.out.println("Exception occured while loading config: " + e.getMessage());
			LOG.error("Exception occured while loading config: {}", e);
		} finally {
			if(null != lit) {
				LineIterator.closeQuietly(lit);
			}
		}
		this.clientBlackList = Collections.unmodifiableSet(tmpClientSet);
	}
	
	public boolean isBlackList(String id) {
		if(null == this.clientBlackList || this.clientBlackList.isEmpty()) {
			return false;
		} else if(null != this.clientBlackList && !this.clientBlackList.isEmpty() && this.clientBlackList.contains(id)) {
			return true;
		}
		return false;
	}
}
