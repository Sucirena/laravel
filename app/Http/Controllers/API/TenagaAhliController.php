<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Http\Resources\TenagaAhliResource;
use App\Models\RiwayatPendidikanTenagaAhli;
use App\Models\TenagaAhli;
use App\Models\User;
use App\Http\Requests\StoreUserRequest;
use App\Http\Requests\UpdateUserRequest;
use Illuminate\Validation\Rule;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\DB;
use Illuminate\Http\JsonResponse;

class TenagaAhliController extends BaseController
{
    /**
     * Display a listing of the resource.
     */
    public function index(): JsonResponse
    {
        $tenagaAhli = TenagaAhli::with(['user', 'riwayatPendidikan'])->get();

        if ($tenagaAhli->isEmpty()) {
            return $this->sendError('Data tenaga ahli kosong.', [], 404);
        }
        return $this->sendResponse(TenagaAhliResource::collection($tenagaAhli), 'Data tenaga ahli berhasil diterima.');
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(StoreUserRequest $request): JsonResponse
    {
        DB::beginTransaction();
    
        try {
            $user = User::create([
                'role' => $request->role,
                'email' => $request->email,
                'password' => Hash::make($request->password),
                'nama' => $request->nama,
                'jenis_kelamin' => $request->jenis_kelamin,
                'tanggal_lahir' => $request->tanggal_lahir,
                'foto_profil' => $request->foto_profil,
            ]);
            
            $tenagaAhli = TenagaAhli::create([
                'id_user' => $user->id,
                'nomor_str' => $request->nomor_str,
                'spesialisasi' => $request->spesialisasi,
                'jadwal_aktif' => $request->jadwal_aktif,
                'lokasi_praktik' => $request->lokasi_praktik,
                'biaya_konsultasi' => $request->biaya_konsultasi,
            ]);

            if ($request->has('riwayat_pendidikan')) {
                foreach ($request->riwayat_pendidikan as $riwayat) {
                    RiwayatPendidikanTenagaAhli::create([
                        'id_tenaga_ahli' => $tenagaAhli->id,
                        'keterangan' => $riwayat['keterangan'],
                    ]);
                }
            }
    
            DB::commit();

            $tenagaAhli->load(['user', 'riwayatPendidikan']);
    
            return $this->sendResponse(new TenagaAhliResource($tenagaAhli), 'Data tenaga ahli berhasil ditambah.');
        } catch (\Exception $e) {
            DB::rollBack();
    
            return $this->sendError('Data tenaga ahli gagal ditambah.', [$e->getMessage()], 500);
        }
    }

    /**
     * Display the specified resource.
     */
    public function show(string $id):JsonResponse{
        $tenagaAhli = TenagaAhli::with(['user', 'riwayatPendidikan'])->find($id);

        if (!$tenagaAhli) {
            return $this->sendError('Data tenaga ahli tidak ditemukan.', [], 404);
        }

        return $this->sendResponse(new TenagaAhliResource($tenagaAhli), 'Data tenaga ahli berhasil diterima.');
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(UpdateUserRequest $request, $id): JsonResponse
    {
        DB::beginTransaction();

        try {
            $tenagaAhli = TenagaAhli::with('user')->find($id);
            if (!$tenagaAhli) {
                return $this->sendError('Data tenaga ahli tidak ditemukan.', [], 404);
            }
    
            $user = $tenagaAhli->user;
    
            $request->validate([
                'email' => [
                    'required',
                    'email',
                    Rule::unique('user', 'email')->ignore($user->id),
                ],
            ]);
    
            $user->update([
                'email' => $request->email,
                'password' => $request->filled('password') ? Hash::make($request->password) : $user->password,
                'nama' => $request->nama,
                'jenis_kelamin' => $request->jenis_kelamin,
                'tanggal_lahir' => $request->tanggal_lahir,
                'foto_profil' => $request->foto_profil,
            ]);
    
            $tenagaAhli->update([
                'nomor_str' => $request->nomor_str,
                'spesialisasi' => $request->spesialisasi,
                'jadwal_aktif' => $request->jadwal_aktif,
                'lokasi_praktik' => $request->lokasi_praktik,
                'biaya_konsultasi' => $request->biaya_konsultasi,
            ]);
            
            if ($request->has('riwayat_pendidikan')) {
                foreach ($request->riwayat_pendidikan as $riwayat) {
                    RiwayatPendidikanTenagaAhli::create([
                        'id_tenaga_ahli' => $tenagaAhli->id,
                        'keterangan' => $riwayat['keterangan'],
                    ]);
                }
            }
    
            DB::commit();

            return $this->sendResponse(new TenagaAhliResource($tenagaAhli), 'Data tenaga ahli berhasil diperbarui.');
        } catch (\Exception $e) {
            DB::rollBack();

            return $this->sendError('Data tenaga ahli gagal diperbarui.', [$e->getMessage()], 500);
        }
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(string $id): JsonResponse{
        $tenagaAhli = TenagaAhli::with('user')->find($id);

        if (!$tenagaAhli) {
            return $this->sendError('Data tenaga ahli tidak ditemukan.', [], 404);
        }

        $user = $tenagaAhli->user;
        $user->delete();

        return $this->sendResponse(new TenagaAhliResource($tenagaAhli), 'Data tenaga ahli berhasil dihapus.');
    }
}
