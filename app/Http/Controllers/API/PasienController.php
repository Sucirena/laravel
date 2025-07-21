<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Http\Resources\PasienResource;
use App\Models\Pasien;
use App\Models\User;
use App\Http\Requests\StoreUserRequest;
use App\Http\Requests\UpdateUserRequest;
use Illuminate\Validation\Rule;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\DB;
use Illuminate\Http\JsonResponse;

class PasienController extends BaseController
{
    /**
     * Display a listing of the resource.
     */
    public function index(): JsonResponse
    {
        $pasien = Pasien::with('user')->get();

        if ($pasien->isEmpty()) {
            return $this->sendError('Data pasien kosong.', [], 404);
        }
        return $this->sendResponse(PasienResource::collection($pasien), 'Data pasien berhasil diterima.');
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
    
            $pasien = Pasien::create([
                'id_user' => $user->id,
                'deskripsi_diri' => $request->deskripsi_diri,
            ]);
    
            DB::commit();
    
            $pasien->load('user');
    
            return $this->sendResponse(new PasienResource($pasien), 'Data pasien berhasil ditambah.');
        } catch (\Exception $e) {
            DB::rollBack();
    
            return $this->sendError('Data pasien gagal ditambah.', [$e->getMessage()], 500);
        }
    }

    /**
     * Display the specified resource.
     */
    public function show(string $id): JsonResponse
    {
        $pasien = Pasien::with('user')->find($id);

        if (!$pasien) {
            return $this->sendError('Data pasien tidak ditemukan.', [], 404);
        }

        return $this->sendResponse(new PasienResource($pasien), 'Data pasien berhasil diterima.');
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(UpdateUserRequest $request, $id): JsonResponse
    {
        DB::beginTransaction();
    
        try {
            $pasien = Pasien::with('user')->find($id);
            if (!$pasien) {
                return $this->sendError('Data pasien tidak ditemukan.', [], 404);
            }
            
            $user = $pasien->user;
    
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
    
            $pasien->update([
                'deskripsi_diri' => $request->deskripsi_diri,
            ]);
    
            DB::commit();
    
            return $this->sendResponse(new PasienResource($pasien), 'Data pasien berhasil diperbarui.');
        } catch (\Exception $e) {
            DB::rollBack();
    
            return $this->sendError('Data pasien gagal diperbarui.', [$e->getMessage()], 500);
        }
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(string $id): JsonResponse{
        $pasien = Pasien::with('user')->find($id);

        if (!$pasien) {
            return $this->sendError('Data pasien tidak ditemukan.', [], 404);
        }

        $user = $pasien->user;
        $user->delete();

        return $this->sendResponse(new PasienResource($pasien), 'Data pasien berhasil dihapus.');
    }
}
