from flask import Flask, render_template, session, redirect, url_for, jsonify, request, make_response
from google.cloud import datastore
import json
import requests

import base64

from six.moves.urllib.request import urlopen
from jose import jwt

from os import environ as env
from urllib.parse import quote_plus, urlencode
from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv

import constants

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

ALGORITHMS = ["RS256"]

datastore_client = datastore.Client()

app = Flask(__name__)

app.secret_key = env.get("APP_SECRET_KEY")

oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)

# This code is adapted from
# https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header.


def verify_jwt(request, raise_error=True):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        if raise_error:
            raise AuthError({"code": "no auth header",
                             "description":
                             "Authorization header is missing"}, 401)
        else:
            return None

    jsonurl = urlopen(
        "https://" +
        env.get("AUTH0_DOMAIN") +
        "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        if raise_error:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Invalid header. "
                                "Use an RS256 signed JWT Access Token"}, 401)
        else:
            return None

    if unverified_header["alg"] == "HS256":
        if raise_error:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Invalid header. "
                                "Use an RS256 signed JWT Access Token"}, 401)
        else:
            return None

    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=env.get("AUTH0_CLIENT_ID"),
                issuer="https://" + env.get("AUTH0_DOMAIN") + "/"
            )
        except jwt.ExpiredSignatureError:
            if raise_error:
                raise AuthError({"code": "token_expired",
                                "description": "token is expired"}, 401)
            else:
                return None

        except jwt.JWTClaimsError:
            if raise_error:
                raise AuthError({"code": "invalid_claims",
                                 "description": "incorrect claims,"
                                 " please check the audience and issuer"},
                                401)
            else:
                return None

        except Exception:
            if raise_error:
                raise AuthError({"code": "invalid_header",
                                "description":
                                    "Unable to parse authentication"
                                    " token."}, 401)
            else:
                return None

        return payload
    else:
        if raise_error:
            raise AuthError({"code": "no_rsa_key",
                             "description":
                             "No RSA key in JWKS"}, 401)
        else:
            return None


@app.route("/")
def root():
    return render_template(
        "index.html",
        session=session.get('user'),
        uid=session.get('unique_id'))


# Decode the JWT supplied in the Authorization header.
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload


@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True))


@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token

    request_headers = {"Authorization": "Bearer " + token['id_token']}
    response = requests.get(
        constants.app_url + "/decode",
        headers=request_headers)

    if response.status_code == 200:
        payload = response.json()
        session["unique_id"] = payload["sub"]
        # verify that the user is in the datastore and if not, add them
        query = datastore_client.query(kind=constants.users)
        query.add_filter('owner', '=', payload['sub'])
        results = list(query.fetch())
        if len(results) == 0:
            new_user = datastore.Entity(
                key=datastore_client.key(
                    constants.users))
            new_user.update({"owner": payload['sub']})
            datastore_client.put(new_user)
        else:
            print("User already in datastore.")
    else:
        print("Failed to decode JWT to JSON.")

    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("root", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID")
            },
            quote_via=quote_plus,
        )
    )


@app.route('/users', methods=['GET'])
def users_get():
    if 'application/json' not in request.accept_mimetypes:
        return ('', 406)

    if request.method == 'GET':
        query = datastore_client.query(kind=constants.users)
        results = list(query.fetch())
        for e in results:
            e["id"] = e.key.id
        return jsonify(results)
    else:
        return (jsonify(error="Method not allowed"), 405)


@app.route('/songs', methods=['GET', 'POST'])
def songs_get_post():
    if 'application/json' not in request.accept_mimetypes:
        return ('', 406)

    if request.method == 'POST':
        error_message = "The request object is missing a required attribute, or the value of an attribute is invalid"
        content = request.get_json()

        # verify that content has the required fields
        if "title" not in content or "artist" not in content:
            return (jsonify(error_message), 400)
        # verify that all fields are strings
        for key in content:
            if not isinstance(content[key], str):
                return (jsonify(error_message), 400)

        new_song = datastore.entity.Entity(
            key=datastore_client.key(constants.songs))
        new_song.update({"title": content["title"],
                         "artist": content["artist"],
                         "album": content["album"]})
        datastore_client.put(new_song)
        new_song["id"] = new_song.key.id
        new_song["self"] = construct_url("songs", new_song.key.id)
        return (new_song, 201)

    elif request.method == 'GET':
        cursor = request.args.get('cursor')
        if cursor:
            cursor = base64.urlsafe_b64decode(cursor.encode('utf-8'))

        # perform aggregation query to get total number of songs
        count = get_entity_count(constants.songs)

        # perform paginated query to get songs
        results, next_cursor = get_resource_paginated(constants.songs, cursor)

        if next_cursor:
            response = {'songs': results, 'next': env.get("APP_URL") + '/songs?cursor=' +
                        base64.urlsafe_b64encode(next_cursor).decode('utf-8'), 'count': str(count)}
        else:
            response = {
                'songs': results,
                'count': str(count)
            }

        for e in response['songs']:
            e["id"] = e.key.id
            e["self"] = construct_url("songs", e.key.id)
            if 'playlists' in e.keys():
                for pid in e['playlists']:
                    pid['self'] = construct_url("playlists", pid['id'])

        return (jsonify(response), 200)

    else:
        return (jsonify(error="Method not allowed"), 405)


@app.route('/songs/<id>', methods=['GET', 'PATCH', 'PUT', 'DELETE'])
def songs_get_patch_put_delete(id):
    if 'application/json' not in request.accept_mimetypes and request.method != 'DELETE':
        return ('', 406)

    song_key = datastore_client.key(constants.songs, int(id))
    song = datastore_client.get(key=song_key)
    if song is None:
        error_json = {"Error": "No song with this song_id exists"}
        return (json.dumps(error_json), 404)

    if request.method == 'DELETE':
        playlist_query = datastore_client.query(kind=constants.playlists)
        for playlist in playlist_query.fetch():
            if 'songs' in playlist.keys():
                for sid in playlist['songs']:
                    if sid['id'] == song.id:
                        playlist['songs'].remove(sid)
                        datastore_client.put(playlist)
        datastore_client.delete(song_key)
        return ('', 204)

    elif request.method == 'PATCH':
        content = request.get_json()
        for key in content:
            if key in ["title", "artist", "album"]:
                if not isinstance(content[key], str):
                    return (
                        jsonify(
                            error="The request object is missing a required attribute, or the value of an attribute is invalid"),
                        400)
                song.update({key: content[key]})
        datastore_client.put(song)
        song["id"] = song.key.id
        song["self"] = construct_url("songs", song.key.id)
        if 'playlists' in song.keys():
            for pid in song['playlists']:
                pid['self'] = construct_url("playlists", pid)
        return (jsonify(song), 200)

    elif request.method == 'PUT':
        content = request.get_json()
        for attribute in ["title", "artist", "album"]:
            if attribute not in content or not isinstance(
                    content[attribute], str):
                return (
                    jsonify(
                        error="The request object is missing a required attribute, or the value of an attribute is invalid"),
                    400)
        song.update({"title": content["title"],
                     "album": content["album"],
                     "artist": content["artist"]})
        datastore_client.put(song)
        song["id"] = song.key.id
        song["self"] = construct_url("songs", song.key.id)
        if 'playlists' in song.keys():
            for pid in song['playlists']:
                pid['self'] = construct_url("playlists", pid)

        res = make_response(jsonify(song))
        res.mimetype = 'application/json'
        res.status_code = 303
        res.headers['Location'] = song["self"]
        return res

    elif request.method == 'GET':
        song["id"] = song.key.id
        song["self"] = construct_url("songs", song.key.id)
        if 'playlists' in song.keys():
            for pid in song['playlists']:
                pid['self'] = construct_url("playlists", pid['id'])
        return (jsonify(song), 200)


@app.route('/playlists', methods=['GET', 'POST'])
def playlists_get_post():
    if 'application/json' not in request.accept_mimetypes:
        return ('', 406)

    payload = verify_jwt(request, raise_error=False)
    if payload is None:
        return (jsonify("Invalid or missing JWT in the request"), 401)

    if request.method == 'POST':
        error_message = "The request object is missing a required attribute, or the value of an attribute is invalid"
        content = request.get_json()

        if "name" not in content or not isinstance(content["name"], str):
            return (jsonify(error_message), 400)

        # Verify that name is unique for this user
        query = datastore_client.query(kind=constants.playlists)
        query.add_filter("owner", "=", payload["sub"])
        query.add_filter("name", "=", content["name"])
        results = list(query.fetch())
        if len(results) > 0:
            return (
                jsonify("The attribute name in the request object is not unique to this user"),
                403)

        new_playlist = datastore.entity.Entity(
            key=datastore_client.key(constants.playlists))
        new_playlist.update({"name": content["name"]})

        # Set the owner of this playlist to the unique identifier of the user
        # who created it
        new_playlist.update({"owner": payload["sub"]})

        if "description" in content and isinstance(
                content["description"], str):
            new_playlist.update({"description": content["description"]})

        new_playlist.update({"count": 0})
        datastore_client.put(new_playlist)
        new_playlist["id"] = new_playlist.key.id
        new_playlist["self"] = construct_url("playlists", new_playlist.key.id)
        return (new_playlist, 201)

    elif request.method == 'GET':
        cursor = request.args.get('cursor')
        if cursor:
            cursor = base64.urlsafe_b64decode(cursor.encode('utf-8'))

        # get total number of playlists
        count = get_entity_count(constants.playlists, payload)

        # get owner's playlists
        results, next_cursor = get_resource_paginated(
            constants.playlists, cursor, payload)

        if next_cursor:
            response = {'playlists': results, 'next': env.get("APP_URL") + '/playlists?cursor=' +
                        base64.urlsafe_b64encode(next_cursor).decode('utf-8'), 'count': str(count)}
        else:
            response = {
                'playlists': results,
                'count': str(count)
            }

        for e in response['playlists']:
            e["id"] = e.key.id
            e["self"] = construct_url("playlists", e.key.id)
            if 'songs' in e.keys():
                for sid in e['songs']:
                    sid['self'] = construct_url("songs", sid['id'])

        return (jsonify(response), 200)

    else:
        return (jsonify(error="Method not allowed"), 405)


@app.route('/playlists/<id>', methods=['GET', 'PATCH', 'PUT', 'DELETE'])
def playlists_get_patch_put_delete(id):
    missing_or_invalid_attribute = "The request object is missing a required attribute, or the value of an attribute is invalid"

    if 'application/json' not in request.accept_mimetypes and request.method != 'DELETE':
        return ('', 406)

    payload = verify_jwt(request, raise_error=False)
    if payload is None:
        return (jsonify("Invalid or missing JWT in the request"), 401)

    playlist_key = datastore_client.key(constants.playlists, int(id))
    playlist = datastore_client.get(key=playlist_key)

    if playlist is None:
        error_json = {"Error": "No playlist with this playlist_id exists"}
        return (json.dumps(error_json), 404)

    if playlist["owner"] != payload["sub"]:
        return (jsonify("Invalid or missing JWT in the request"), 401)

    if request.method == 'DELETE':
        datastore_client.delete(playlist_key)
        return ('', 204)

    elif request.method == 'PATCH':
        content = request.get_json()
        for key in content:
            if key in ["name", "description"]:
                if not isinstance(content[key], str):
                    return (jsonify(error=missing_or_invalid_attribute), 400)
                playlist.update({key: content[key]})
        datastore_client.put(playlist)
        playlist["id"] = playlist.key.id
        playlist["self"] = construct_url("playlists", playlist.key.id)
        if 'songs' in playlist.keys():
            for sid in playlist['songs']:
                sid['self'] = construct_url("songs", sid['id'])
        return (jsonify(playlist), 200)

    elif request.method == 'PUT':
        content = request.get_json()

        if "name" not in content or not isinstance(content["name"], str):
            return (jsonify(error=missing_or_invalid_attribute), 400)
        playlist.update({"name": content["name"]})

        if "description" in playlist and "description" not in content:
            return (jsonify(error=missing_or_invalid_attribute), 400)
        if "description" in content and isinstance(
                content["description"], str):
            playlist.update({"description": content["description"]})

        datastore_client.put(playlist)
        playlist["id"] = playlist.key.id
        playlist["self"] = construct_url("playlists", playlist.key.id)
        if 'songs' in playlist.keys():
            for sid in playlist['songs']:
                sid['self'] = construct_url("songs", sid)
        res = make_response(jsonify(playlist))
        res.mimetype = 'application/json'
        res.status_code = 303
        res.headers['Location'] = playlist["self"]
        return res

    elif request.method == 'GET':
        playlist["id"] = playlist.key.id
        playlist["self"] = construct_url("playlists", playlist.key.id)
        if 'songs' in playlist.keys():
            for sid in playlist['songs']:
                sid['self'] = construct_url("songs", sid['id'])
        return (jsonify(playlist), 200)


@app.route('/playlists/<playlist_id>/songs/<song_id>',
           methods=['PUT', 'DELETE'])
def playlists_add_del_song(playlist_id, song_id):
    payload = verify_jwt(request, raise_error=False)
    if payload is None:
        return (jsonify("Invalid or missing JWT in the request"), 401)

    playlist_key = datastore_client.key(constants.playlists, int(playlist_id))
    playlist = datastore_client.get(key=playlist_key)

    if playlist is None:
        error_json = {"Error": "No playlist with this playlist_id exists"}
        return (json.dumps(error_json), 404)

    song_key = datastore_client.key(constants.songs, int(song_id))
    song = datastore_client.get(key=song_key)
    if song is None:
        error_json = {"Error": "No song with this song_id exists"}
        return (json.dumps(error_json), 404)

    if playlist["owner"] != payload["sub"]:
        return (jsonify("Invalid or missing JWT in the request"), 401)

    if request.method == 'PUT':
        if 'songs' in playlist.keys():
            playlist['songs'].append({"id": song.id})
        else:
            playlist['songs'] = [{"id": song.id}]
        if 'playlists' in song.keys():
            song['playlists'].append({"id": playlist.id})
        else:
            song['playlists'] = [{"id": playlist.id}]
        playlist['count'] += 1
        datastore_client.put(playlist)
        datastore_client.put(song)
        return ('', 200)

    elif request.method == 'DELETE':
        if 'songs' in playlist.keys():
            for sid in playlist['songs']:
                if sid['id'] == song.id:
                    playlist['songs'].remove(sid)
                    playlist['count'] -= 1
                    datastore_client.put(playlist)
        if 'playlists' in song.keys():
            for pid in song['playlists']:
                if pid['id'] == playlist.id:
                    song['playlists'].remove(pid)
                    datastore_client.put(song)
        return ('', 200)


def construct_url(resource, id):
    return constants.app_url + "/" + resource + "/" + str(id)

# get the number of entities of a given kind.
# If owner and payload are provided, only count entities owned by the user.


def get_entity_count(kind, payload=None):
    query_count = 0
    query = datastore_client.query(kind=kind)
    if payload is not None:
        query.add_filter("owner", "=", payload["sub"])
    agg_query = datastore_client.aggregation_query(
        query).count()
    query_result = agg_query.fetch()
    for aggregation_results in query_result:
        for aggregation in aggregation_results:
            query_count = aggregation.value
    return query_count

# get a list of entities of a given kind.
# If owner and payload are provided, only get entities owned by the user.


def get_resource_paginated(kind, cursor, payload=None, limit=5):
    query = datastore_client.query(kind=kind)
    if payload is not None:
        query.add_filter("owner", "=", payload["sub"])
    query_iter = query.fetch(start_cursor=cursor, limit=limit)
    page = next(query_iter.pages, [])
    results = list(page)
    next_cursor = query_iter.next_page_token
    return results, next_cursor


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)
