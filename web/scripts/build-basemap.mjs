import { mkdir, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { feature } from "topojson-client";

const require = createRequire(import.meta.url);
const statesTopology = require("us-atlas/states-10m.json");
const countiesTopology = require("us-atlas/counties-10m.json");
const outputDirectory = resolve("public/maps");

const CONTIGUOUS_STATE_FIPS = new Set([
  "01", "04", "05", "06", "08", "09", "10", "11", "12", "13",
  "16", "17", "18", "19", "20", "21", "22", "23", "24", "25",
  "26", "27", "28", "29", "30", "31", "32", "33", "34", "35",
  "36", "37", "38", "39", "40", "41", "42", "44", "45", "46",
  "47", "48", "49", "50", "51", "53", "54", "55", "56",
]);
const ARKANSAS_BORDER_STATE_FIPS = new Set([
  "05", // Arkansas
  "22", // Louisiana
  "48", // Texas
  "28", // Mississippi
  "29", // Missouri
  "40", // Oklahoma
  "47", // Tennessee
]);
const STATE_ABBREVIATIONS = {
  "01": "AL", "04": "AZ", "05": "AR", "06": "CA", "08": "CO",
  "09": "CT", "10": "DE", "11": "DC", "12": "FL", "13": "GA",
  "16": "ID", "17": "IL", "18": "IN", "19": "IA", "20": "KS",
  "21": "KY", "22": "LA", "23": "ME", "24": "MD", "25": "MA",
  "26": "MI", "27": "MN", "28": "MS", "29": "MO", "30": "MT",
  "31": "NE", "32": "NV", "33": "NH", "34": "NJ", "35": "NM",
  "36": "NY", "37": "NC", "38": "ND", "39": "OH", "40": "OK",
  "41": "OR", "42": "PA", "44": "RI", "45": "SC", "46": "SD",
  "47": "TN", "48": "TX", "49": "UT", "50": "VT", "51": "VA",
  "53": "WA", "54": "WV", "55": "WI", "56": "WY",
};
const SOURCE = "U.S. Census Bureau 2017 cartographic boundaries via us-atlas 3.0.1";

function fips(id, width) {
  return String(id ?? "").padStart(width, "0");
}

function asFeatureCollection(topology, objectName, predicate, decorate) {
  const collection = feature(topology, topology.objects[objectName]);
  const features = (collection.type === "FeatureCollection" ? collection.features : [collection])
    .filter(predicate)
    .map(decorate);
  return { type: "FeatureCollection", features };
}

const states = asFeatureCollection(
  statesTopology,
  "states",
  (state) => CONTIGUOUS_STATE_FIPS.has(fips(state.id, 2)),
  (state) => ({
    ...state,
    properties: {
      ...state.properties,
      state_fips: fips(state.id, 2),
      abbreviation: STATE_ABBREVIATIONS[fips(state.id, 2)],
    },
  }),
);

const counties = asFeatureCollection(
  countiesTopology,
  "counties",
  (county) => ARKANSAS_BORDER_STATE_FIPS.has(fips(county.id, 5).slice(0, 2)),
  (county) => {
    const countyFips = fips(county.id, 5);
    const stateFips = countyFips.slice(0, 2);
    return {
      ...county,
      properties: {
        ...county.properties,
        geoid: countyFips,
        state_fips: stateFips,
        state_abbreviation: STATE_ABBREVIATIONS[stateFips],
      },
    };
  },
);

if (states.features.length !== CONTIGUOUS_STATE_FIPS.size || counties.features.length < 250) {
  throw new Error(`Unexpected basemap feature counts: ${states.features.length} states, ${counties.features.length} counties.`);
}

await mkdir(outputDirectory, { recursive: true });
await writeFile(
  resolve(outputDirectory, "conus-states-v1.geojson"),
  JSON.stringify({ ...states, source: SOURCE }),
);
await writeFile(
  resolve(outputDirectory, "arkansas-border-counties-v1.geojson"),
  JSON.stringify({ ...counties, source: SOURCE }),
);
console.log(`Built local basemap: ${states.features.length} contiguous states/DC, ${counties.features.length} Arkansas-border counties.`);
