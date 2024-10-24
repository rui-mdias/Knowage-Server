package it.eng.knowage.encryption;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jasypt.encryption.pbe.PBEStringEncryptor;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;

import it.eng.spagobi.tools.dataset.bo.IDataSet;
import it.eng.spagobi.tools.dataset.common.datastore.IDataStore;
import it.eng.spagobi.tools.dataset.common.datastore.IField;
import it.eng.spagobi.tools.dataset.common.datastore.IRecord;
import it.eng.spagobi.tools.dataset.common.metadata.IFieldMetaData;
import it.eng.spagobi.tools.dataset.common.metadata.IMetaData;
import it.eng.spagobi.tools.dataset.common.metadata.MetaData;
import it.eng.spagobi.tools.dataset.common.transformer.AbstractDataStoreTransformer;

public class DecryptionDataStoreTransformer extends AbstractDataStoreTransformer {

	private static final Logger LOGGER = LogManager.getLogger(DecryptionDataStoreTransformer.class);

	private boolean needDecryption = false;
	private final Map<Integer, IFieldMetaData> decryptableFieldByIndex = new LinkedHashMap<>();
	private PBEStringEncryptor encryptor;
	private final IMetaData dataStoreMetadata;

	public DecryptionDataStoreTransformer(IDataSet dataSet) {
		this(dataSet.getDsMetadata() != null && !dataSet.getDsMetadata().equals("") && !dataSet.getDsMetadata().equals("[]")
				&& !dataSet.getDsMetadata().startsWith("{") ? dataSet.getMetadata() : new MetaData());
	}

	public DecryptionDataStoreTransformer(IDataStore dataStore) {
		this(dataStore.getMetaData());
	}

	public DecryptionDataStoreTransformer(IMetaData dataStoreMetadata) {
		this.dataStoreMetadata = dataStoreMetadata;
		try {
			setUpDecryption();
		} catch (Exception e) {
			LOGGER.error("Encryption initialization error: check setUpDecryption method", e);
		}
	}

	@Override
	public void transformDataSetRecords(IDataStore dataStore) {
		for (IRecord currRecord : dataStore.getRecords()) {
			decryptIfNeeded(currRecord);
		}

	}

	@Override
	public void transformDataSetMetaData(IDataStore dataStore) {
		// Not needed
	}

	private void setUpDecryption() {
		AtomicInteger index = new AtomicInteger();

		// @formatter:off
		LOGGER.debug("Looking for fields which need decrypt...");
		dataStoreMetadata.getFieldsMeta()
			.stream()
			.collect(Collectors.toMap(e -> index.getAndIncrement(), e -> e))
			.entrySet()
			.stream()
			.peek(e -> {
				LOGGER.debug("Current field: {}", e);
			})
			.filter(e -> e.getValue().isDecrypt())
			.forEach(e -> {
				Integer key = e.getKey();
				IFieldMetaData value = e.getValue();
				decryptableFieldByIndex.put(key, value);

				LOGGER.debug("\tField to decrypt: {}", value);
			});
		// @formatter:on

		LOGGER.debug("Decryptable field map is {}", decryptableFieldByIndex);
		needDecryption = !decryptableFieldByIndex.isEmpty();

		LOGGER.debug("Need decryption? {}", needDecryption);
		if (needDecryption) {
			LOGGER.debug("Decryption needed. Instantiating the encryptor...");
			encryptor = EncryptorFactory.getInstance().createDefault();
			LOGGER.debug("Encryptor is {}", encryptor);
		} else {
			LOGGER.debug("Encryptor not needed");
		}

	}

	private void decryptIfNeeded(IRecord currRecord) {
		if (needDecryption) {
			LOGGER.debug("Decrypting record {}", currRecord);
			List<IField> fields = currRecord.getFields();

			for (int i = 0; i < fields.size(); i++) {
				LOGGER.debug("Current field {}", i);
				if (decryptableFieldByIndex.containsKey(i)) {
					LOGGER.debug("Decrypting field {}: {}", i, decryptableFieldByIndex.get(i));
					decrypt(currRecord, i);
				}
			}
		}
	}

	private void decrypt(IRecord currRecord, int i) {
		IFieldMetaData fieldMetaData = decryptableFieldByIndex.get(i);
		String fieldName = fieldMetaData.getName();
		String fieldAlias = fieldMetaData.getAlias();
		IField fieldAt = currRecord.getFieldAt(i);
		Object value = fieldAt.getValue();
		String newValue = null;

		try {
			if (Objects.nonNull(value)) {
				newValue = encryptor.decrypt(value.toString());
				fieldAt.setValue(newValue);
				LOGGER.debug("Decrypt value {} to {}", value, newValue);
			}
		} catch (EncryptionOperationNotPossibleException e) {
			LOGGER.warn("Ignoring field value {} from field {} (with \"{}\" alias): see following message", value,
					fieldName, fieldAlias);
			LOGGER.warn("Cannot decrypt column: see the previous message", e);
		} catch (EncryptionInitializationException e) {
			LOGGER.error("Encryption initialization error: check decryption system properties", e);
		}
	}

	private String mapFieldKey(IFieldMetaData field) {
		return field.getName();
	}

}