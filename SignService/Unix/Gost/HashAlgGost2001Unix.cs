﻿using SignService.Unix.Api;
using SignService.Unix.Utils;
using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;
using static SignService.CApiExtConst;

namespace SignService.Unix.Gost
{
	/// <summary>
	/// Класс для получения хэш функции по ГОСТ 34.11-2001 под Linux, используя .NET
	/// </summary>
	[ComVisible(true)]
	public sealed class HashAlgGost2001Unix : HashAlgorithm
	{
		[SecurityCritical]
		private IntPtr unsafeHashHandle;

		[ComVisible(false)]
		public IntPtr HashHandle
		{
			[ComVisible(false)]
			[SecurityCritical]
			[SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
			get => this.InternalHashHandle;
		}

		internal IntPtr InternalHashHandle
		{
			[SecurityCritical]
			get
			{
				return this.unsafeHashHandle;
			}
		}

		[SecuritySafeCritical]
		public HashAlgGost2001Unix()
		{
			this.HashSizeValue = Gost3411Consts.HashSizeValue;
			IntPtr invalidHandle = IntPtr.Zero;
			UnixExtUtil.CreateHash(UnixExtUtil.StaticGost2001ProvHandle, Gost3411Consts.HashAlgId, ref invalidHandle);
			this.unsafeHashHandle = invalidHandle;
		}

		[SecuritySafeCritical]
		public override void Initialize()
		{
			if (this.unsafeHashHandle != null && this.unsafeHashHandle != IntPtr.Zero)
			{
				CApiExtUnix.CryptDestroyHash(unsafeHashHandle); //dispose
			}

			IntPtr invalidHandle = IntPtr.Zero;
			UnixExtUtil.CreateHash(UnixExtUtil.StaticGost2001ProvHandle, Gost3411Consts.HashAlgId, ref invalidHandle);
			this.unsafeHashHandle = invalidHandle;
		}

		[SecuritySafeCritical]
		protected override void HashCore(byte[] rgb, int ibStart, int cbSize)
		{
			if (rgb != null && rgb.Length > 0 && cbSize > 0)
			{
				UnixExtUtil.HashData(this.unsafeHashHandle, rgb, ibStart, cbSize);
			}
		}

		[SecuritySafeCritical]
		protected override byte[] HashFinal()
		{
			return UnixExtUtil.EndHash(this.unsafeHashHandle);
		}

		[SecuritySafeCritical]
		protected override void Dispose(bool disposing)
		{
			if (this.unsafeHashHandle != null && this.unsafeHashHandle != IntPtr.Zero)
			{
				CApiExtUnix.CryptDestroyHash(unsafeHashHandle);
			}

			base.Dispose(disposing);
		}
	}
}
