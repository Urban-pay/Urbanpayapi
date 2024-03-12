<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class deleteduser extends Model
{
    use HasFactory;
    protected $fillable = [
        'name',
        'email',
        'username',
        'phoneno',
        'password',
        'pin',
        'otp',
    ];
}
