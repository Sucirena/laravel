<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\API\UserController;
use App\Http\Controllers\API\AdminController;
use App\Http\Controllers\API\TenagaAhliController;
use App\Http\Controllers\API\PasienController;
use App\Http\Controllers\API\RiwayatPendidikanTenagaAhliController;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');

Route::apiResource('user', UserController::class)->only(['index', 'show']);
Route::apiResource('admin', AdminController::class);
Route::apiResource('tenaga-ahli', TenagaAhliController::class);
Route::apiResource('pasien', PasienController::class);
Route::apiResource('riwayat-pendidikan', RiwayatPendidikanTenagaAhliController::class)->only(['index', 'destroy']);