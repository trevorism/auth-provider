package com.trevorism.util


import com.google.gson.JsonDeserializationContext
import com.google.gson.JsonDeserializer
import com.google.gson.JsonElement

import java.lang.reflect.Type
import java.time.Instant

class JsonDateDeserializer implements JsonDeserializer<Date> {

    Date deserialize(JsonElement json, Type date, JsonDeserializationContext context) {
        String stringDate = json.getAsJsonPrimitive().getAsString()
        try {
            return new Date(Long.parseLong(stringDate))
        } catch (NumberFormatException e) {
            return Date.from(Instant.parse(stringDate))
        }
    }
}
