<?php

use Illuminate\Http\Request;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

/*Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});*/

/*Route::group([

    'middleware' => 'api',
    'prefix' => 'auth'

], function ($router) {

    Route::post('login', 'AuthController@login');
    Route::post('logout', 'AuthController@logout');
    Route::post('refresh', 'AuthController@refresh');
    Route::post('me', 'AuthController@me');

});*/

Route::post('register', 'ApiController@register');
Route::post('login', 'ApiController@authenticate');
Route::get('open', 'DataController@open');
Route::any('userprofile/{id}', 'ApiController@getUserProfile');

Route::group(['middleware' => ['jwt.verify']], function() {
    Route::get('user', 'ApiController@getAuthenticatedUser');
    Route::any('edituser', 'ApiController@updateAuthenticatedUser');
    Route::get('closed', 'DataController@closed');
});
