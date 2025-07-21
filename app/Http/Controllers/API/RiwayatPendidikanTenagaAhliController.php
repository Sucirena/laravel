<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Http\Resources\RiwayatPendidikanTenagaAhliResource;
use App\Models\RiwayatPendidikanTenagaAhli;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class RiwayatPendidikanTenagaAhliController extends BaseController
{
    /**
     * Display a listing of the resource.
     */
    public function index(): JsonResponse
    {
        $riwayatPendidikanTenagaAhli = RiwayatPendidikanTenagaAhli::all();
    
        if ($riwayatPendidikanTenagaAhli->isEmpty()) {
            return $this->sendError('Data riwayat pendidikan tenaga ahli kosong.', [], 404);
        }
    
        return $this->sendResponse(RiwayatPendidikanTenagaAhliResource::collection($riwayatPendidikanTenagaAhli), 'Data riwayat pendidikan tenaga ahli berhasil diterima.');
    }
    

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        //
    }

    /**
     * Display the specified resource.
     */
    public function show(string $id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, string $id)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(string $id): JsonResponse
    {
        $riwayatPendidikanTenagaAhli = RiwayatPendidikanTenagaAhli::with('tenagaAhli')->find($id);
    
        if (!$riwayatPendidikanTenagaAhli) {
            return $this->sendError('Data riwayat pendidikan tenaga ahli tidak ditemukan.', [], 404);
        }
    
        $riwayatPendidikanTenagaAhli->delete();
    
        return $this->sendResponse(new RiwayatPendidikanTenagaAhliResource($riwayatPendidikanTenagaAhli), 'Data riwayat pendidikan tenaga ahli berhasil dihapus.');
    }
}
