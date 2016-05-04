from django.http import HttpResponse, \
                        HttpResponseRedirect
from django.core.urlresolvers import reverse
from django.template.context import RequestContext
from django.shortcuts import render_to_response
from django.views.decorators.http import require_POST

import requests
import re


api_base_url = 'https://datahub.csail.mit.edu'
our_base_url = 'http://localhost:8000'
client_id = 'client_id'
client_secret = ('foo'
                 'bar'
                 'baz')
owner_username = 'jander'
owner_password = 'foo'


def _authorization_url():
    url_format = ('{base}/oauth2/authorize?'
                  'response_type=code&'
                  'scope=read+write&'
                  'client_id={client_id}&'
                  'redirect_uri={redirect_uri}')
    return url_format.format(
        base=api_base_url,
        client_id=client_id,
        redirect_uri=our_base_url)


def _exchange_code_for_token(code):
    token_url = '{base}/oauth2/token/'.format(base=api_base_url)

    response = requests.post(token_url, data={
        'code': code,
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': our_base_url,
        'grant_type': 'authorization_code',
        })

    return response.json()['access_token']


def _update_username_for_current_session(request):
    access_token = request.session['access_token']
    user_url = '{base}/api/v1/user'.format(base=api_base_url)
    # Act as the user to find out what their username is.
    headers = {
        'Authorization': 'Bearer {token}'.format(token=access_token)}
    response = requests.get(user_url, headers=headers)
    if response.status_code == 200 and 'username' in response.json():
        username = response.json()['username']
        request.session['username'] = username
        return username


def _post_query(request, query):
    user_url = '{base}/api/v1/query/{repo_base}'.format(
        base=api_base_url, repo_base=owner_username)
    # Run queries as the app owner
    headers = {
        'Authorization': 'Bearer {token}'.format(
            token=request.session['owner_access_token'])}
    requests.post(user_url, headers=headers, data={'query': query})


def _form_input_value(text, name):
    regexp = "name='{}' value='([^']+)'"
    result = re.search(regexp.format(name), text)
    if not result:
        regexp = "name=\"{}\" type=\"hidden\" value=\"([^\"]+)\""
        result = re.search(regexp.format(name), text)
    if not result:
        regexp = "name=\"{}\" value=\"([^\"]+)\""
        result = re.search(regexp.format(name), text)
    return result.groups()[0]


def _repo_owner_access_token(request):
    # Use existing owner token if one already exists.
    # if 'owner_access_token' in request.session:
    #     return request.session['owner_access_token']
    # Otherwise, do the authorization dance server-side.
    session = requests.Session()
    # Go to the authorization page, get redirected to log in.
    response = session.get(_authorization_url())
    # Pick out the login form's values and post them along with the owner's
    # credentials.
    csrf_token = _form_input_value(response.text, 'csrfmiddlewaretoken')
    next_url = _form_input_value(response.text, 'next')

    headers = {'Referer': '{base}/'.format(base=api_base_url)}
    form_url = '{base}/account/login'.format(base=api_base_url)
    response = session.post(form_url, headers=headers, data={
        'csrfmiddlewaretoken': csrf_token,
        'next': next_url,
        'username': owner_username,
        'password': owner_password,
        })

    # Get redirected to the authorization form, pick out its values and post
    # those to approve self.
    csrf_token = _form_input_value(response.text, 'csrfmiddlewaretoken')
    redirect_uri = _form_input_value(response.text, 'redirect_uri')
    scope = _form_input_value(response.text, 'scope')
    cid = _form_input_value(response.text, 'client_id')
    response_type = _form_input_value(response.text, 'response_type')

    form_url = "{base}/oauth2/authorize/".format(base=api_base_url)
    response = session.post(form_url, headers=headers, data={
        'csrfmiddlewaretoken': csrf_token,
        'redirect_uri': redirect_uri,
        'scope': scope,
        'client_id': cid,
        'state': "",
        'response_type': response_type,
        'allow': "Authorize",
        }, allow_redirects=False)
    # Grab the code from the redirect URL
    # e.g. 'http://localhost:8000?code=VubcXxXEJrdtrycMUU1J0IWJbTHJfG'
    code = response.headers['location'].partition("?code=")[-1]
    # Get the owner access token
    token = _exchange_code_for_token(code)
    request.session['owner_access_token'] = token
    return token


def home(request):
    context = RequestContext(request, {
        'authorize_url': _authorization_url(),
        })

    # If this is a redirect from DataHub after being authorized by the user,
    # use the given code to get an access token from DataHub.
    if 'code' in request.GET:
        code = request.GET['code']
        access_token = _exchange_code_for_token(code)
        # Save the token in this session for later reuse.
        request.session['access_token'] = access_token
        # Redirect to this same page, minus the OAuth query parameters.
        return HttpResponseRedirect(reverse('home-page'))

    if 'access_token' in request.session:
        username = _update_username_for_current_session(request)
        _give_user_access_to_table(request, username)
        context.update({'username': username})

    return render_to_response('index.html', context)


def logout(request):
    request.session.flush()
    return HttpResponseRedirect(reverse('home-page'))


@require_POST
def mark(request):
    # Matches a table created with:
    #   CREATE TABLE location.locations (username varchar, latitude float,
    #   longitude float, timestamp timestamp);
    query = ("INSERT INTO {repo}.{table} (username, latitude, "
             "longitude, timestamp) "
             "VALUES ('{username}', '{latitude}', "
             "'{longitude}', '{timestamp}')").format(
                repo="location",
                table="locations",
                username=request.session['username'],
                latitude=request.POST['latitude'],
                longitude=request.POST['longitude'],
                timestamp=request.POST['timestamp'])
    print(query)
    _post_query(request, query)
    return HttpResponse("Thanks!")


def _give_user_access_to_table(request, username):
    # Get the access token that lets us modify policies.
    owner_access_token = _repo_owner_access_token(request)
    print(owner_access_token)
    # Add a policy for this user if they don't already have one.
    # query = "INSERT INTO repo.policy_table VALUES (policy)"
    # _post_query(request, query)
