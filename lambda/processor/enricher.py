import boto3

ec2_client = boto3.client("ec2")

ENVIRONMENT_SCORES = {
    "production": 10,
    "prod":       10,
    "staging":    6,
    "stage":      6,
    "development": 3,
    "dev":        3,
}

EXPOSURE_SCORES = {
    "NETWORK_REACHABLE": 10,
    "NETWORK_ACCESSIBLE": 10,
    "NOT_APPLICABLE": 1,
}


def get_asset_criticality(resource_tags: dict) -> float:
    env = resource_tags.get("environment", resource_tags.get("Environment", "")).lower()
    score = ENVIRONMENT_SCORES.get(env, 5)
    tier = resource_tags.get("tier", resource_tags.get("Tier", "")).lower()
    if tier == "web":
        score = min(score + 1, 10)
    return float(score)


def get_exposure_score(network_reachability: str) -> float:
    return float(EXPOSURE_SCORES.get(network_reachability, 5))


def get_resource_tags(instance_id: str) -> dict:
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        reservations = response.get("Reservations", [])
        if not reservations:
            return {}
        instances = reservations[0].get("Instances", [])
        if not instances:
            return {}
        tags = instances[0].get("Tags", [])
        return {tag["Key"]: tag["Value"] for tag in tags}
    except Exception:
        return {}
