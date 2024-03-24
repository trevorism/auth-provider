package com.trevorism.util


import com.google.gson.JsonDeserializationContext
import com.google.gson.JsonDeserializer
import com.google.gson.JsonElement

import java.lang.reflect.Type

class JsonDateDeserializer implements JsonDeserializer<Date> {

    Date deserialize(JsonElement json, Type date, JsonDeserializationContext context) {
        String stringDate = json.getAsJsonPrimitive().getAsString()
        return new Date(Long.parseLong(stringDate))
    }
}
