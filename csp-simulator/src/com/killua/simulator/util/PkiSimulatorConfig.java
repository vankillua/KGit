package com.killua.simulator.util;

import java.net.URL;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.FileConfiguration;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.commons.configuration.reloading.FileChangedReloadingStrategy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class PkiSimulatorConfig {
	
	private PkiSimulatorConfig() {
		super();
	}
	
	private static final Logger LOG = LoggerFactory.getLogger(PkiSimulatorConfig.class);
	
	private static FileConfiguration config = null;
	
	static {
		try {
			URL url = PkiSimulatorConfig.class.getClassLoader().getResource("app.properties");
			if (null == url) {
				throw new Exception("Cannot find the resource: app.properties");
			}
			config = new PropertiesConfiguration(url);
			config.setEncoding("UTF-8");
			config.setReloadingStrategy(new FileChangedReloadingStrategy());
		} catch (final Exception e) {
			LOG.error("PkiSimulatorConfig Exception: {}", e);
		}
	}
	
	public static String getString(final String propertyName) {
		return config.getString(propertyName);
	}
	
	public static String getString(final String propertyName, final String defaultValue) {
		return config.getString(propertyName, defaultValue);
	}
	
	public static int getInt(final String propertyName) {
        return config.getInt(propertyName);
    }

    public static int getInt(final String propertyName, final int defaultValue) {
        return config.getInt(propertyName, defaultValue);
    }

    public static boolean getBoolean(final String propertyName) {
        return config.getBoolean(propertyName);
    }

    public static boolean getBoolean(final String propertyName, final boolean defaultValue) {
        return config.getBoolean(propertyName, defaultValue);
    }
    
    public static void setProperty(String propertyName, Object propertyValue) {
        try {
            config.setProperty(propertyName, propertyValue);
            config.save();
        } catch (ConfigurationException e) {
            LOG.error("Exception occured while writing app.properties: {}", e);
        }
    }
}
