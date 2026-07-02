import com.sap.it.api.mapping.*;
import groovy.json.JsonSlurper;
import java.io.StringReader;
import java.util.Map;
import java.util.List;

public void JDBCLookup_METRO_LOCATION_XREF_LookupKey_SAP_SITE(String[] key, Output output, MappingContext context) throws Exception {

    try {

        // Read lookup hashmap property
        String rowObjectsJson = context.getProperty("METRO_LOCATION_XREF_LookupKey_SAP_SITE");

        if (rowObjectsJson == null || rowObjectsJson.isEmpty()) {
            output.addValue("");
            return;
        }

        // Parse JSON
        JsonSlurper slurper = new JsonSlurper();
        Map rowObjects = (Map) slurper.parse(new StringReader(rowObjectsJson));

        // Process all input occurrences
        for (int i = 0; i < key.length; i++) {

            String currentKey = key[i];

            if (currentKey == null || currentKey.trim().isEmpty()) {
                output.addValue("");
                continue;
            }

            // Lookup using SAP_SITE key
            List rows = (List) rowObjects.get(currentKey);

            if (rows != null && rows.size() > 0) {

                // First matched row
                Map firstRow = (Map) rows.get(0);

                // Fetch required column
                String witronOwner = firstRow.get("WITRON_OWNER") != null
                    ? firstRow.get("WITRON_OWNER").toString()
                    : "";

                output.addValue(witronOwner);

            } else {
                output.addValue("");
            }
        }

    } catch (Exception e) {
        output.addValue("ERROR: " + e.getMessage());
    }
}