<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Admin extends Model
{
    use HasFactory;

    // Tentukan nama tabel jika tidak menggunakan pluralisasi default dari Laravel
    protected $table = 'admin';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'id_user',
        'admin_role',
    ];

    /**
     * Define relationship to the User model.
     * Setiap admin berhubungan dengan satu pengguna (User).
     */
    public function user(){
        return $this->belongsTo(User::class, 'id_user');
    }

    public $timestamps = false;
}