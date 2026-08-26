import logging
from dataclasses import dataclass
from typing import Iterable

from sqlalchemy import text
from sqlalchemy.orm import Session


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Geofence:
    geofence_id: str
    name: str
    polygon_wkt: str


DEFAULT_GEOFENCES: tuple[Geofence, ...] = (
    Geofence(
        geofence_id="demo-nova-hq",
        name="NOVA HQ Demo Fence",
        polygon_wkt="POLYGON((-122.42 37.77,-122.40 37.77,-122.40 37.79,-122.42 37.79,-122.42 37.77))",
    ),
)


def point_in_polygon_wkt(polygon_wkt: str, longitude: float, latitude: float) -> bool:
    """Ray-casting containment test, dialect independent (portable mode)."""
    body = polygon_wkt[polygon_wkt.find("((") + 2 : polygon_wkt.rfind("))")]
    ring: list[tuple[float, float]] = []
    for chunk in body.split(","):
        parts = chunk.split()
        if len(parts) >= 2:
            ring.append((float(parts[0]), float(parts[1])))
    if len(ring) < 4:
        return False
    inside = False
    j = len(ring) - 1
    for i in range(len(ring)):
        xi, yi = ring[i]
        xj, yj = ring[j]
        if (yi > latitude) != (yj > latitude):
            intersect_x = (xj - xi) * (latitude - yi) / (yj - yi) + xi
            if longitude < intersect_x:
                inside = not inside
        j = i
    return inside


def check_event_against_geofences_local(device_id: str, longitude: float, latitude: float, geofences: Iterable[Geofence] = DEFAULT_GEOFENCES) -> list[dict]:
    """Containment check without any database dependency (SQLite mode)."""
    return [
        {"device_id": device_id, "geofence_id": fence.geofence_id, "name": fence.name}
        for fence in geofences
        if point_in_polygon_wkt(fence.polygon_wkt, longitude, latitude)
    ]


def check_event_against_geofences(db: Session, device_id: str, longitude: float, latitude: float, geofences: Iterable[Geofence] = DEFAULT_GEOFENCES) -> list[dict]:
    matches: list[dict] = []
    for fence in geofences:
        inside = db.execute(
            text(
                """
                SELECT ST_Contains(
                    ST_GeomFromText(:polygon, 4326),
                    ST_SetSRID(ST_MakePoint(:longitude, :latitude), 4326)
                ) AS inside
                """
            ),
            {"polygon": fence.polygon_wkt, "longitude": longitude, "latitude": latitude},
        ).scalar()
        if inside:
            matches.append({"device_id": device_id, "geofence_id": fence.geofence_id, "name": fence.name})
    return matches


def parse_wkt_polygon(polygon_wkt: str) -> list[dict]:
    body = polygon_wkt[polygon_wkt.find("((") + 2 : polygon_wkt.rfind("))")]
    coords = []
    for chunk in body.split(","):
        parts = chunk.split()
        if len(parts) >= 2:
            coords.append({"longitude": float(parts[0]), "latitude": float(parts[1])})
    return coords


def list_geofences_as_dicts() -> list[dict]:
    return [
        {
            "geofence_id": f.geofence_id,
            "name": f.name,
            "polygon_wkt": f.polygon_wkt,
            "coords": parse_wkt_polygon(f.polygon_wkt),
        }
        for f in DEFAULT_GEOFENCES
    ]
